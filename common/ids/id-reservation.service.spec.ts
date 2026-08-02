import { PrismaClient } from '@prisma/client'
import {
  IdReservationError,
  IdReservationService,
  RESERVABLE_TABLES,
  ReservableTable,
} from './id-reservation.service'
import {
  createAdditionalClient,
  resetTestDatabase,
  startTestDatabase,
  stopTestDatabase,
} from '../../../test/db-test-harness'

/**
 * اختبارات تكامل على Postgres حقيقي.
 *
 * RESERVABLE_TABLES فاضية في 1a، فبنسجّل جدول اختباري عليها مؤقتاً
 * (outbox_messages) عشان نتحقق من الآلية نفسها. أول جدول حقيقي هيتسجّل
 * في المرحلة 1b.
 */

const TEST_KEY = '__spec_outbox'
const TEST_TARGET: ReservableTable = { table: 'outbox_messages', column: 'id' }

describe('IdReservationService (integration)', () => {
  let prisma: PrismaClient
  let service: IdReservationService

  beforeAll(async () => {
    prisma = await startTestDatabase()
    ;(RESERVABLE_TABLES as Record<string, ReservableTable>)[TEST_KEY] = TEST_TARGET
    service = new IdReservationService(prisma as never)
  }, 120_000)

  afterAll(async () => {
    delete (RESERVABLE_TABLES as Record<string, ReservableTable>)[TEST_KEY]
    await stopTestDatabase()
  })

  beforeEach(async () => {
    await resetTestDatabase()
  })

  it('reserves a bigint id', async () => {
    const id = await service.reserve(TEST_KEY)
    expect(typeof id).toBe('bigint')
    expect(id).toBeGreaterThan(0n)
  })

  it('never returns the same id twice', async () => {
    const ids = await Promise.all(
      Array.from({ length: 50 }, () => service.reserve(TEST_KEY)),
    )
    expect(new Set(ids.map(String)).size).toBe(50)
  })

  it('reserves a batch of distinct ids', async () => {
    const ids = await service.reserveMany(TEST_KEY, 20)
    expect(ids).toHaveLength(20)
    expect(new Set(ids.map(String)).size).toBe(20)
  })

  it('does not recycle an id across separate connections', async () => {
    const second = createAdditionalClient()
    const secondService = new IdReservationService(second as never)

    try {
      const batches = await Promise.all([
        service.reserveMany(TEST_KEY, 100),
        secondService.reserveMany(TEST_KEY, 100),
      ])
      const all = batches.flat().map(String)
      expect(new Set(all).size).toBe(200)
    } finally {
      await second.$disconnect()
    }
  })

  it('does not recycle an id when the caller transaction rolls back', async () => {
    let reserved: bigint | undefined

    await expect(
      prisma.$transaction(async () => {
        reserved = await service.reserve(TEST_KEY)
        throw new Error('rollback')
      }),
    ).rejects.toThrow('rollback')

    const afterRollback = await service.reserve(TEST_KEY)

    // ده جوهر القرار: المعرّف اللي اتربط بيه نص مشفّر ماينفعش يرجع
    expect(afterRollback).toBeGreaterThan(reserved as bigint)
  })

  it('tolerates gaps in the sequence', async () => {
    const first = await service.reserve(TEST_KEY)
    await service.reserveMany(TEST_KEY, 10) // متستخدمش
    const later = await service.reserve(TEST_KEY)

    expect(later - first).toBeGreaterThan(1n)
  })

  it('rejects an unregistered table', async () => {
    await expect(service.reserve('does_not_exist')).rejects.toThrow(
      IdReservationError,
    )
  })

  it('rejects invalid batch sizes', async () => {
    await expect(service.reserveMany(TEST_KEY, 0)).rejects.toThrow(
      IdReservationError,
    )
    await expect(service.reserveMany(TEST_KEY, -1)).rejects.toThrow(
      IdReservationError,
    )
    await expect(service.reserveMany(TEST_KEY, 1.5)).rejects.toThrow(
      IdReservationError,
    )
    await expect(service.reserveMany(TEST_KEY, 1001)).rejects.toThrow(
      IdReservationError,
    )
  })

  it('produces ids usable as explicit primary keys', async () => {
    const id = await service.reserve(TEST_KEY)

    await prisma.outboxMessage.create({
      data: {
        id,
        store_id: 1n,
        mode: 'live',
        aggregate_type: 'spec',
        aggregate_id: '1',
        event_type: 'spec.event',
        payload: {},
        occurred_at: new Date(),
      },
    })

    const found = await prisma.outboxMessage.findFirst({
      where: { id, store_id: 1n, mode: 'live' },
    })
    expect(found?.id).toBe(id)
  })
})
