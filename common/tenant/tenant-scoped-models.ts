/**
 * سجل الموديلات المشمولة بحارس العزل.
 *
 * التسجيل صريح عن قصد: الحارس مابيفحصش أي موديل مش مكتوب هنا، فمفيش
 * أي تأثير على أي كود موجود في المشروع.
 *
 * المرحلة 1a: تلات جداول بس — دول أول جداول فيها store_id تحت سيطرتنا.
 * المرحلة 1b هتضيف كيانات الدفع والـ checkout.
 */
export interface TenantScopedModel {
  /** اسم الموديل زي ما هو في Prisma (مش اسم الجدول) */
  readonly model: string
  readonly storeField: string
  /** null لو الموديل مالوش وضع test/live */
  readonly modeField: string | null
}

export const TENANT_SCOPED_MODELS: readonly TenantScopedModel[] = [
  {
    model: 'PaymentIdempotencyRecord',
    storeField: 'store_id',
    modeField: 'mode',
  },
  { model: 'OutboxMessage', storeField: 'store_id', modeField: 'mode' },
  { model: 'ConsumedEvent', storeField: 'store_id', modeField: 'mode' },
]

const BY_MODEL: ReadonlyMap<string, TenantScopedModel> = new Map(
  TENANT_SCOPED_MODELS.map((entry) => [entry.model, entry]),
)

export function getTenantScopedModel(
  model: string | undefined,
): TenantScopedModel | undefined {
  if (!model) return undefined
  return BY_MODEL.get(model)
}

/** عمليات القراءة — بتتفحص الـ where */
export const READ_OPERATIONS = new Set([
  'findUnique',
  'findUniqueOrThrow',
  'findFirst',
  'findFirstOrThrow',
  'findMany',
  'count',
  'aggregate',
  'groupBy',
])

/** عمليات التعديل والحذف — بتتفحص الـ where كمان */
export const WRITE_WITH_WHERE_OPERATIONS = new Set([
  'update',
  'updateMany',
  'delete',
  'deleteMany',
  'upsert',
])

/** عمليات الإنشاء — بتتفحص الـ data */
export const CREATE_OPERATIONS = new Set([
  'create',
  'createMany',
  'createManyAndReturn',
])
