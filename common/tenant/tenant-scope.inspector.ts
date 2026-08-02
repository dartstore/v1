import {
  CREATE_OPERATIONS,
  READ_OPERATIONS,
  WRITE_WITH_WHERE_OPERATIONS,
  getTenantScopedModel,
} from './tenant-scoped-models'

/**
 * ══════════════════════════════════════════════════════════════════
 * فحص نطاق المستأجر — منطق خالص
 * ══════════════════════════════════════════════════════════════════
 *
 * منفصل عن الـ extension عن قصد: كده المنطق بيتغطّى باختبارات وحدة
 * من غير قاعدة بيانات ومن غير عميل Prisma مولّد.
 *
 * ⚠️ الفحص **بيبلّغ بس**. مابيعدّلش الاستعلام، ومابيضيفش شروط، ومابيمنعش
 * أي عملية. القرار ده مقصود (قرارك: log-only, no query rewriting,
 * no hidden behavior) عشان مايبقاش في سلوك خفي بيغيّر نتايج الاستعلامات
 * من ورا المطوّر.
 */

export type ScopeViolationKind =
  /** استعلام على موديل مشمول من غير store_id في الـ where */
  | 'missing_store_scope'
  /** استعلام من غير mode في الـ where */
  | 'missing_mode_scope'
  /** إنشاء صف من غير store_id في الـ data */
  | 'missing_store_value'
  /** إنشاء صف من غير mode في الـ data */
  | 'missing_mode_value'
  /** الاستعلام بيستهدف متجر غير المتجر اللي في سياق الطلب */
  | 'store_scope_mismatch'

export interface ScopeViolation {
  readonly kind: ScopeViolationKind
  readonly model: string
  readonly operation: string
  readonly detail: string
}

export interface InspectionInput {
  readonly model: string | undefined
  readonly operation: string
  readonly args: unknown
  /** معرّف المتجر من سياق الطلب، لو موجود */
  readonly contextStoreId?: string | null
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

/**
 * هل الحقل مقيّد في الـ where؟
 *
 * بيدوّر جوه AND كمان، لأن الشكل ده شائع:
 *   where: { AND: [{ store_id: 1n }, { status: 'pending' }] }
 *
 * OR مابيتحسبش عن قصد: شرط جوه OR ممكن يتحقق من غير ما الحقل يتقيّد،
 * فوجوده هناك مش ضمانة عزل.
 */
function fieldConstrained(where: unknown, field: string): boolean {
  if (!isRecord(where)) return false
  if (Object.prototype.hasOwnProperty.call(where, field)) return true

  const and = where.AND
  if (Array.isArray(and)) {
    return and.some((clause) => fieldConstrained(clause, field))
  }
  if (isRecord(and)) return fieldConstrained(and, field)

  return false
}

/** يستخرج قيمة الحقل لو كانت قيمة مباشرة أو بشكل { equals } */
function extractScalar(where: unknown, field: string): unknown {
  if (!isRecord(where)) return undefined

  const direct = where[field]
  if (direct !== undefined) {
    if (isRecord(direct) && 'equals' in direct) return direct.equals
    return direct
  }

  const and = where.AND
  if (Array.isArray(and)) {
    for (const clause of and) {
      const found = extractScalar(clause, field)
      if (found !== undefined) return found
    }
  }

  return undefined
}

/** بيرجّع صفوف الـ data سواء كانت صف واحد أو مجموعة */
function payloadsOf(args: unknown): unknown[] {
  if (!isRecord(args)) return []
  const data = args.data
  if (Array.isArray(data)) return data
  if (isRecord(data)) return [data]
  return []
}

export function inspectScope(input: InspectionInput): ScopeViolation[] {
  const scoped = getTenantScopedModel(input.model)
  if (!scoped) return [] // موديل مش مسجّل → مفيش أي فحص

  const model = scoped.model
  const { operation, args, contextStoreId } = input
  const violations: ScopeViolation[] = []

  const check = (kind: ScopeViolationKind, detail: string) =>
    violations.push({ kind, model, operation, detail })

  if (CREATE_OPERATIONS.has(operation)) {
    for (const payload of payloadsOf(args)) {
      if (!isRecord(payload)) continue

      if (payload[scoped.storeField] === undefined) {
        check('missing_store_value', `data.${scoped.storeField} غير موجود`)
      }
      if (scoped.modeField && payload[scoped.modeField] === undefined) {
        check('missing_mode_value', `data.${scoped.modeField} غير موجود`)
      }
    }
    return violations
  }

  if (
    READ_OPERATIONS.has(operation) ||
    WRITE_WITH_WHERE_OPERATIONS.has(operation)
  ) {
    const where = isRecord(args) ? args.where : undefined

    if (!fieldConstrained(where, scoped.storeField)) {
      check('missing_store_scope', `where.${scoped.storeField} غير موجود`)
    } else if (contextStoreId != null) {
      const value = extractScalar(where, scoped.storeField)
      if (value !== undefined && String(value) !== String(contextStoreId)) {
        check(
          'store_scope_mismatch',
          `where.${scoped.storeField}=${String(value)} بينما سياق الطلب ${contextStoreId}`,
        )
      }
    }

    if (scoped.modeField && !fieldConstrained(where, scoped.modeField)) {
      check('missing_mode_scope', `where.${scoped.modeField} غير موجود`)
    }

    if (operation === 'upsert') {
      const createPayload = isRecord(args) ? args.create : undefined
      if (
        isRecord(createPayload) &&
        createPayload[scoped.storeField] === undefined
      ) {
        check('missing_store_value', `create.${scoped.storeField} غير موجود`)
      }
    }
  }

  return violations
}
