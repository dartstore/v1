import { ConfigService } from '@nestjs/config'
import { PrismaClient } from '@prisma/client'
import { IdempotencyService } from './idempotency.service'
import {
  createAdditionalClient,
  resetTestDatabase,
  startTestDatabase,
  stopTestDatabase,
} from '../../../test/db-test-harness'

/**
 * اختبارات تكامل على Postgres حقيقي.
 *
 * الفحوص النقية (canonicalize / fingerprint / validateKey) موجودة في
 * idempotency.types.spec.ts. دي بتركّز على السلوكيات اللي مستحيل
 * تتأكد بـ mock: التوازي الحقيقي، القيد الفريد، وسرقة الحجز المنتهي.
 */

const STORE = 1n
const OTHER_STORE = 2n

/**
 * الخدمة بتقرا مساحة 'idempotency' كاملة عن طريق getOrThrow،
 * فالستَب بيرجّع الكائن مش مفاتيح منقوطة.
 */
function makeConfig(): ConfigService {
  return {
    getOrThrow: (key: string) => {
      if (key === 'idempotency') return { ttlSeconds: 3600, leaseSeconds: 60 }
      throw new Error(`missing config: ${key}`)
    },
  } as unknown as ConfigService
}

function baseRequest(
  overrides: Partial<Parameters<IdempotencyService['claim']>[0]> = {},
) {
  return {
    storeId: STORE,
    mode: 'live' as const,
    scope: 'spec.operation',
    idempotencyKey: 'key-1',
    fingerprint: 'fp-1',
    ttlSeconds: 3600,
    leaseSeconds: 60,
    ...overrides,
  }
}

describe('IdempotencyService (integration)', () => {
  let prisma: PrismaClient
  let service: IdempotencyService

  beforeAll(async () => {
    prisma = await startTestDatabase()
    service = new IdempotencyService(prisma as never, makeConfig())
  }, 120_000)

  afterAll(async () => {
    await stopTestDatabase()
  })

  beforeEach(async () => {
    await resetTestDatabase()
  })

  it('lets the first request proceed', async () => {
    const result = await service.claim(baseRequest())
    expect(result.outcome).toBe('proceed')
  })

  it('replays the stored response for an identical repeat', async () => {
    const first = await service.claim(baseRequest())
    if (first.outcome !== 'proceed') throw new Error('expected proceed')

    await service.complete(first.recordId, STORE, 201, { id: 'pi_123' })

    const second = await service.claim(baseRequest())
    expect(second).toMatchObject({
      outcome: 'replay',
      statusCode: 201,
      body: { id: 'pi_123' },
    })
  })

  it('stores an empty response body without throwing', async () => {
    const first = await service.claim(baseRequest())
    if (first.outcome !== 'proceed') throw new Error('expected proceed')

    // Prisma بيرفض null عادية على عمود Json — الخدمة بتستخدم DbNull
    await expect(
      service.complete(first.recordId, STORE, 204, undefined),
    ).resolves.not.toThrow()

    const second = await service.claim(baseRequest())
    expect(second).toMatchObject({ outcome: 'replay', statusCode: 204 })
  })

  it('returns conflict for the same key with a different body', async () => {
    const first = await service.claim(baseRequest())
    if (first.outcome !== 'proceed') throw new Error('expected proceed')
    await service.complete(first.recordId, STORE, 200, { ok: true })

    const second = await service.claim(
      baseRequest({ fingerprint: 'fp-DIFFERENT' }),
    )
    expect(second.outcome).toBe('conflict')
  })

  it('blocks a concurrent in-flight duplicate instead of double-executing', async () => {
    await service.claim(baseRequest())
    const second = await service.claim(baseRequest())

    expect(second.outcome).toBe('in_flight')
    if (second.outcome === 'in_flight') {
      expect(second.retryAfterSeconds).toBeGreaterThan(0)
    }
  })

  it('allows exactly one winner under real parallel claims', async () => {
    const other = createAdditionalClient()
    const otherService = new IdempotencyService(other as never, makeConfig())

    try {
      const results = await Promise.all([
        service.claim(baseRequest()),
        otherService.claim(baseRequest()),
        service.claim(baseRequest()),
        otherService.claim(baseRequest()),
      ])

      expect(results.filter((r) => r.outcome === 'proceed')).toHaveLength(1)
      expect(results.filter((r) => r.outcome === 'in_flight')).toHaveLength(3)
    } finally {
      await other.$disconnect()
    }
  })

  it('resumes a claim whose lease has expired', async () => {
    const first = await service.claim(baseRequest({ leaseSeconds: -1 }))
    if (first.outcome !== 'proceed') throw new Error('expected proceed')

    const second = await service.claim(baseRequest())
    expect(second).toMatchObject({
      outcome: 'proceed',
      recordId: first.recordId,
    })
  })

  it('clears a stale response body when a lease is stolen', async () => {
    const first = await service.claim(baseRequest({ leaseSeconds: -1 }))
    if (first.outcome !== 'proceed') throw new Error('expected proceed')

    await service.fail(first.recordId, STORE)

    const resumed = await service.claim(baseRequest())
    expect(resumed.outcome).toBe('proceed')

    const record = await prisma.paymentIdempotencyRecord.findFirst({
      where: { id: first.recordId, store_id: STORE, mode: 'live' },
    })
    expect(record?.status).toBe('in_flight')
    expect(record?.response_body).toBeNull()
    expect(record?.response_status_code).toBeNull()
  })

  it('allows retry after a failure', async () => {
    const first = await service.claim(baseRequest())
    if (first.outcome !== 'proceed') throw new Error('expected proceed')

    await service.fail(first.recordId, STORE)

    const second = await service.claim(baseRequest())
    expect(second.outcome).toBe('proceed')
  })

  it('isolates identical keys across stores', async () => {
    const a = await service.claim(baseRequest({ storeId: STORE }))
    const b = await service.claim(baseRequest({ storeId: OTHER_STORE }))

    expect(a.outcome).toBe('proceed')
    expect(b.outcome).toBe('proceed')
  })

  it('isolates identical keys across modes', async () => {
    const live = await service.claim(baseRequest({ mode: 'live' }))
    const test = await service.claim(baseRequest({ mode: 'test' }))

    expect(live.outcome).toBe('proceed')
    expect(test.outcome).toBe('proceed')
  })

  it('isolates identical keys across scopes', async () => {
    const a = await service.claim(baseRequest({ scope: 'op.a' }))
    const b = await service.claim(baseRequest({ scope: 'op.b' }))

    expect(a.outcome).toBe('proceed')
    expect(b.outcome).toBe('proceed')
  })

  it("does not complete another store's record", async () => {
    const first = await service.claim(baseRequest())
    if (first.outcome !== 'proceed') throw new Error('expected proceed')

    await service.complete(first.recordId, OTHER_STORE, 200, { leaked: true })

    const record = await prisma.paymentIdempotencyRecord.findFirst({
      where: { id: first.recordId, store_id: STORE, mode: 'live' },
    })
    expect(record?.status).toBe('in_flight')
  })

  it('purges expired records', async () => {
    await service.claim(baseRequest({ ttlSeconds: -10 }))
    await service.claim(baseRequest({ idempotencyKey: 'key-2' }))

    const purged = await service.purgeExpired()
    expect(purged).toBe(1)

    const remaining = await prisma.paymentIdempotencyRecord.count({
      where: { store_id: STORE, mode: 'live' },
    })
    expect(remaining).toBe(1)
  })
})
