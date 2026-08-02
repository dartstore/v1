import { PrismaClient } from '@prisma/client'
import { OutboxService } from './outbox.service'
import { OutboxPayloadError } from './messaging.types'
import {
  resetTestDatabase,
  startTestDatabase,
  stopTestDatabase,
} from '../../../test/db-test-harness'

/**
 * اختبارات تكامل على Postgres حقيقي.
 *
 * الفحوص النقية لسلامة الحمولة موجودة في messaging.types.spec.ts —
 * دي بتركّز على الضمانة اللي مستحيل تتأكد من غير قاعدة بيانات:
 * إن الحدث بيتحفظ ويترجع مع الـ transaction بتاعة المستدعي.
 */

const STORE = 1n

function envelope(overrides: Record<string, unknown> = {}) {
  return {
    storeId: STORE,
    mode: 'live' as const,
    aggregateType: 'checkout',
    aggregateId: '42',
    eventType: 'checkout.committed',
    payload: { checkoutId: '42' },
    ...overrides,
  }
}

describe('OutboxService (integration)', () => {
  let prisma: PrismaClient
  let outbox: OutboxService

  beforeAll(async () => {
    prisma = await startTestDatabase()
    outbox = new OutboxService()
  }, 120_000)

  afterAll(async () => {
    await stopTestDatabase()
  })

  beforeEach(async () => {
    await resetTestDatabase()
  })

  it('writes a message inside the caller transaction', async () => {
    await prisma.$transaction(async (tx) => {
      await outbox.emit(tx, envelope())
    })

    const stored = await prisma.outboxMessage.findFirst({
      where: { store_id: STORE, mode: 'live' },
    })

    expect(stored).toMatchObject({
      event_type: 'checkout.committed',
      status: 'pending',
      event_version: 1,
      attempts: 0,
    })
  })

  it('rolls back with the caller transaction', async () => {
    await expect(
      prisma.$transaction(async (tx) => {
        await outbox.emit(tx, envelope())
        throw new Error('boom')
      }),
    ).rejects.toThrow('boom')

    const count = await prisma.outboxMessage.count({
      where: { store_id: STORE, mode: 'live' },
    })

    // ده جوهر الفكرة: الحالة والحدث بيترجعوا مع بعض
    expect(count).toBe(0)
  })

  it('writes several messages atomically', async () => {
    await prisma.$transaction(async (tx) => {
      await outbox.emitMany(tx, [
        envelope({ eventType: 'a.happened' }),
        envelope({ eventType: 'b.happened' }),
      ])
    })

    expect(
      await prisma.outboxMessage.count({
        where: { store_id: STORE, mode: 'live' },
      }),
    ).toBe(2)
  })

  it('rejects an unsafe payload before writing anything', async () => {
    await expect(
      prisma.$transaction(async (tx) => {
        await outbox.emit(tx, envelope({ payload: { secret_key: 'sk_live' } }))
      }),
    ).rejects.toThrow(OutboxPayloadError)

    expect(await prisma.outboxMessage.count()).toBe(0)
  })

  it('rejects an unsafe payload in a batch without writing any row', async () => {
    await expect(
      prisma.$transaction(async (tx) => {
        await outbox.emitMany(tx, [
          envelope({ eventType: 'safe.event' }),
          envelope({ eventType: 'unsafe.event', payload: { api_key: 'x' } }),
        ])
      }),
    ).rejects.toThrow(OutboxPayloadError)

    expect(await prisma.outboxMessage.count()).toBe(0)
  })

  it('records the business occurrence time separately from creation', async () => {
    const occurredAt = new Date('2026-01-01T00:00:00.000Z')

    await prisma.$transaction(async (tx) => {
      await outbox.emit(tx, envelope({ occurredAt }))
    })

    const stored = await prisma.outboxMessage.findFirst({
      where: { store_id: STORE, mode: 'live' },
    })

    expect(stored?.occurred_at.toISOString()).toBe(occurredAt.toISOString())
    expect(stored?.created_at.getTime()).toBeGreaterThan(occurredAt.getTime())
  })

  it('keeps test and live messages separate', async () => {
    await prisma.$transaction(async (tx) => {
      await outbox.emit(tx, envelope({ mode: 'live' }))
      await outbox.emit(tx, envelope({ mode: 'test' }))
    })

    expect(
      await prisma.outboxMessage.count({
        where: { store_id: STORE, mode: 'live' },
      }),
    ).toBe(1)
    expect(
      await prisma.outboxMessage.count({
        where: { store_id: STORE, mode: 'test' },
      }),
    ).toBe(1)
  })
})
