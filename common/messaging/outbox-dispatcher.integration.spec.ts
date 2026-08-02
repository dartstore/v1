import { ConfigService } from '@nestjs/config'
import { SchedulerRegistry } from '@nestjs/schedule'
import { PrismaClient } from '@prisma/client'
import { ConsumedEventService } from './consumed-event.service'
import { OutboxDispatcherService } from './outbox-dispatcher.service'
import { OutboxHandlerRegistry } from './outbox-handler.registry'
import { OutboxService } from './outbox.service'
import { OutboxHandler, OutboxRecord } from './messaging.types'
import {
  createAdditionalClient,
  resetTestDatabase,
  startTestDatabase,
  stopTestDatabase,
} from '../../../test/db-test-harness'

const STORE = 1n

function makeConfig(overrides: Record<string, unknown> = {}): ConfigService {
  const values: Record<string, unknown> = {
    messaging: {
      dispatcherEnabled: true,
      pollIntervalMs: 5000,
      batchSize: 50,
      leaseSeconds: 60,
      maxAttempts: 3,
      backoffBaseSeconds: 1,
      ...overrides,
    },
  }
  return {
    get: (key: string, fallback: unknown) => values[key] ?? fallback,
    getOrThrow: (key: string) => {
      const value = values[key]
      if (value === undefined) throw new Error(`missing config: ${key}`)
      return value
    },
  } as unknown as ConfigService
}

/**
 * الاختبارات بتنادي dispatchBatch() مباشرةً وماتناديش onModuleInit،
 * فالجدولة مش مستخدمة — الستَب موجود عشان توقيع الـ constructor بس.
 */
function makeScheduler(): SchedulerRegistry {
  return {
    addInterval: () => undefined,
    deleteInterval: () => undefined,
    doesExist: () => false,
  } as unknown as SchedulerRegistry
}

class RecordingHandler implements OutboxHandler {
  readonly seen: bigint[] = []
  constructor(
    readonly consumerName: string,
    private readonly behaviour: (m: OutboxRecord) => Promise<void> = async () => {},
  ) {}
  async handle(message: OutboxRecord): Promise<void> {
    this.seen.push(message.id)
    await this.behaviour(message)
  }
}

async function seed(
  prisma: PrismaClient,
  outbox: OutboxService,
  eventType: string,
) {
  let id!: bigint
  await prisma.$transaction(async (tx) => {
    id = await outbox.emit(tx, {
      storeId: STORE,
      mode: 'live',
      aggregateType: 'spec',
      aggregateId: '1',
      eventType,
      payload: { n: 1 },
    })
  })
  return id
}

describe('OutboxDispatcherService (integration)', () => {
  let prisma: PrismaClient
  let outbox: OutboxService
  let registry: OutboxHandlerRegistry
  let consumed: ConsumedEventService
  let dispatcher: OutboxDispatcherService

  beforeAll(async () => {
    prisma = await startTestDatabase()
    outbox = new OutboxService()
  }, 120_000)

  afterAll(async () => {
    await stopTestDatabase()
  })

  beforeEach(async () => {
    await resetTestDatabase()
    registry = new OutboxHandlerRegistry()
    consumed = new ConsumedEventService(prisma as never)
    dispatcher = new OutboxDispatcherService(
      prisma as never,
      makeConfig(),
      registry,
      consumed,
      makeScheduler(),
    )
  })

  it('delivers a message to its handler', async () => {
    const handler = new RecordingHandler('spec.consumer')
    registry.register('spec.event', handler)

    const id = await seed(prisma, outbox, 'spec.event')
    const processed = await dispatcher.dispatchBatch()

    expect(processed).toBe(1)
    expect(handler.seen).toEqual([id])

    const stored = await prisma.outboxMessage.findFirst({ where: { id } })
    expect(stored?.status).toBe('published')
    expect(stored?.published_at).not.toBeNull()
  })

  it('publishes messages that have no registered handler', async () => {
    const id = await seed(prisma, outbox, 'nobody.listens')
    await dispatcher.dispatchBatch()

    const stored = await prisma.outboxMessage.findFirst({ where: { id } })
    expect(stored?.status).toBe('published')
    expect(stored?.last_error).toBe('no_handlers')
  })

  it('records consumption so redelivery is a no-op', async () => {
    const handler = new RecordingHandler('spec.consumer')
    registry.register('spec.event', handler)

    const id = await seed(prisma, outbox, 'spec.event')
    await dispatcher.dispatchBatch()

    // نرجّعها معلّقة يدوياً — بيحاكي إعادة تسليم
    await prisma.outboxMessage.updateMany({
      where: { id },
      data: { status: 'pending', published_at: null },
    })

    await dispatcher.dispatchBatch()

    // اتسلّمت مرتين، بس المستهلك اشتغل مرة واحدة
    expect(handler.seen).toEqual([id])
  })

  it('gives a message to exactly one worker under real contention', async () => {
    const second = createAdditionalClient()

    try {
      const handlerA = new RecordingHandler('consumer.a')
      const registryB = new OutboxHandlerRegistry()
      const handlerB = new RecordingHandler('consumer.a')

      registry.register('spec.event', handlerA)
      registryB.register('spec.event', handlerB)

      const dispatcherB = new OutboxDispatcherService(
        second as never,
        makeConfig(),
        registryB,
        new ConsumedEventService(second as never),
        makeScheduler(),
      )

      for (let i = 0; i < 20; i += 1) {
        await seed(prisma, outbox, 'spec.event')
      }

      await Promise.all([
        dispatcher.dispatchBatch(),
        dispatcherB.dispatchBatch(),
      ])

      const allSeen = [...handlerA.seen, ...handlerB.seen].map(String)

      // كل رسالة اتعالجت مرة واحدة بالظبط عبر العاملين
      expect(allSeen).toHaveLength(20)
      expect(new Set(allSeen).size).toBe(20)

      const consumedRows = await prisma.consumedEvent.count({
        where: { consumer_name: 'consumer.a' },
      })
      expect(consumedRows).toBe(20)
    } finally {
      await second.$disconnect()
    }
  })

  it('reclaims a message whose lease expired', async () => {
    const id = await seed(prisma, outbox, 'spec.event')

    await prisma.outboxMessage.updateMany({
      where: { id },
      data: {
        status: 'claimed',
        claimed_by: 'dead-worker',
        claim_expires_at: new Date(Date.now() - 60_000),
      },
    })

    const handler = new RecordingHandler('spec.consumer')
    registry.register('spec.event', handler)

    expect(await dispatcher.dispatchBatch()).toBe(1)
    expect(handler.seen).toEqual([id])
  })

  it('does not touch a message whose lease is still valid', async () => {
    const id = await seed(prisma, outbox, 'spec.event')

    await prisma.outboxMessage.updateMany({
      where: { id },
      data: {
        status: 'claimed',
        claimed_by: 'busy-worker',
        claim_expires_at: new Date(Date.now() + 60_000),
      },
    })

    expect(await dispatcher.dispatchBatch()).toBe(0)
  })

  it('retries with exponential backoff and then dead-letters', async () => {
    registry.register(
      'spec.event',
      new RecordingHandler('spec.consumer', async () => {
        throw new Error('handler exploded')
      }),
    )

    const id = await seed(prisma, outbox, 'spec.event')

    for (let attempt = 1; attempt <= 3; attempt += 1) {
      await prisma.outboxMessage.updateMany({
        where: { id },
        data: { next_attempt_at: new Date(Date.now() - 1000) },
      })
      await dispatcher.dispatchBatch()

      const stored = await prisma.outboxMessage.findFirst({ where: { id } })
      expect(stored?.attempts).toBe(attempt)
      expect(stored?.last_error).toContain('handler exploded')

      if (attempt < 3) {
        expect(stored?.status).toBe('pending')
      } else {
        expect(stored?.status).toBe('dead')
      }
    }

    expect(await dispatcher.deadLetterCount()).toBe(1)
  })

  it('does not pick up a message before its next attempt time', async () => {
    registry.register(
      'spec.event',
      new RecordingHandler('spec.consumer', async () => {
        throw new Error('fail')
      }),
    )

    const id = await seed(prisma, outbox, 'spec.event')
    await dispatcher.dispatchBatch()

    // المحاولة الجاية في المستقبل → الدورة دي المفروض متلقطهاش
    expect(await dispatcher.dispatchBatch()).toBe(0)
    expect(
      (await prisma.outboxMessage.findFirst({ where: { id } }))?.attempts,
    ).toBe(1)
  })

  it('rejects duplicate consumer registration', () => {
    registry.register('spec.event', new RecordingHandler('dup'))
    expect(() =>
      registry.register('spec.event', new RecordingHandler('dup')),
    ).toThrow()
  })

  it('reports stale pending messages', async () => {
    const id = await seed(prisma, outbox, 'spec.event')
    await prisma.outboxMessage.updateMany({
      where: { id },
      data: { created_at: new Date(Date.now() - 3_600_000) },
    })

    expect(await dispatcher.stalePendingCount(300)).toBe(1)
  })
})
