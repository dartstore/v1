import { execFileSync } from 'child_process'
import { PrismaClient } from '@prisma/client'
import {
  PostgreSqlContainer,
  StartedPostgreSqlContainer,
} from '@testcontainers/postgresql'

/**
 * ══════════════════════════════════════════════════════════════════
 * بيئة اختبار بقاعدة بيانات حقيقية
 * ══════════════════════════════════════════════════════════════════
 *
 * ليه Postgres حقيقي مش mock:
 *
 * السلوكيات اللي المرحلة 1a قايمة عليها مستحيل تتأكد من غير قاعدة
 * بيانات فعلية:
 *   • حصرية الحجز (lease) بين أكتر من instance
 *   • القيود الفريدة كضمانة للـ idempotency
 *   • رجوع الـ transaction وتأثيره على صندوق الصادر
 *   • ذرّية nextval تحت التوازي
 *
 * الـ mock بيأكد اللي الكود بيعمله، مش اللي المفروض يحصل.
 *
 * الحاوية بتقوم مرة واحدة لكل عملية اختبار (globalSetup مش لكل ملف)،
 * والجداول بتتفضّى بين الاختبارات.
 */

let container: StartedPostgreSqlContainer | undefined
let client: PrismaClient | undefined

/** الجداول اللي بتتفضّى بين الاختبارات — بالترتيب عشان المفاتيح الأجنبية */
const TRUNCATE_ORDER = [
  'consumed_events',
  'outbox_messages',
  'payment_idempotency_records',
]

export async function startTestDatabase(): Promise<PrismaClient> {
  if (client) return client

  container = await new PostgreSqlContainer('postgres:16-alpine')
    .withDatabase('phase1a_test')
    .withUsername('test')
    .withPassword('test')
    .start()

  const url = container.getConnectionUri()

  // db push مش migrate deploy: الاختبارات محتاجة الشكل الحالي للـ schema
  // بس، مش تاريخ الهجرات. أسرع، ومابيعتمدش على وجود مجلد migrations.
  execFileSync(
    'npx',
    ['prisma', 'db', 'push', '--skip-generate', '--accept-data-loss'],
    { env: { ...process.env, DATABASE_URL: url }, stdio: 'pipe' },
  )

  client = new PrismaClient({ datasources: { db: { url } } })
  await client.$connect()

  return client
}

export function getTestClient(): PrismaClient {
  if (!client) {
    throw new Error(
      'قاعدة بيانات الاختبار لسه ماقامتش — نادِ startTestDatabase() في beforeAll.',
    )
  }
  return client
}

export function getTestDatabaseUrl(): string {
  if (!container) {
    throw new Error('حاوية الاختبار مش شغالة.')
  }
  return container.getConnectionUri()
}

/** يفضّي كل جداول المرحلة 1a ويرجّع الـ sequences لأول الرقم */
export async function resetTestDatabase(): Promise<void> {
  const db = getTestClient()
  await db.$executeRawUnsafe(
    `TRUNCATE TABLE ${TRUNCATE_ORDER.join(', ')} RESTART IDENTITY CASCADE`,
  )
}

export async function stopTestDatabase(): Promise<void> {
  await client?.$disconnect()
  await container?.stop()
  client = undefined
  container = undefined
}

/**
 * ينشئ عميل Prisma إضافي بيتصل بنفس القاعدة.
 *
 * ضروري لاختبار التوازي الحقيقي: instance تانية من التطبيق معناها
 * connection pool منفصل، والـ mock مايقدرش يمثّل ده.
 */
export function createAdditionalClient(): PrismaClient {
  return new PrismaClient({ datasources: { db: { url: getTestDatabaseUrl() } } })
}
