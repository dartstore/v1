import { Logger } from '@nestjs/common'
import { Prisma } from '@prisma/client/extension'
import { inspectScope } from './tenant-scope.inspector'
import type { TenantContextService } from './tenant-context.service'

/**
 * ══════════════════════════════════════════════════════════════════
 * حارس عزل المستأجرين — تبليغ فقط
 * ══════════════════════════════════════════════════════════════════
 *
 * بيفحص الاستعلامات على الموديلات المسجّلة في tenant-scoped-models،
 * وبيسجّل تحذير لو الاستعلام مش مقيّد بـ store_id و mode.
 *
 * ثلاث ضمانات صريحة (قرارك):
 *   ❌ مابيعدّلش args — الاستعلام بيتنفّذ زي ما المطوّر كتبه بالظبط.
 *   ❌ مابيضيفش شروط ولا بيعيد كتابة أي حاجة.
 *   ❌ مابيمنعش ولا بيرمي — الفشل في الفحص مايوقفش الطلب.
 *
 * ✅ بيسجّل تحذير بس.
 *
 * السبب: إعادة الكتابة التلقائية بتخلي نتيجة الاستعلام تختلف عن اللي
 * مكتوب في الكود، وده أسوأ من غياب الحارس أصلاً — المطوّر بيثق في
 * كود مش بيعمل اللي مكتوب فيه.
 *
 * ⚠️ الفحص نفسه ملفوف في try/catch: أي خطأ جواه (شكل args غير متوقع
 * مثلاً) لازم مايأثرش على الاستعلام. حارس تبليغ ماينفعش يكسر إنتاج.
 *
 * المرحلة 3 هتحوّل ده لمنع فعلي مع RLS على مستوى Postgres.
 */

export interface TenantGuardOptions {
  /** لو false الـ extension بيعدّي على طول من غير أي فحص */
  readonly enabled: boolean
  readonly tenantContext: TenantContextService
  readonly logger?: Logger
}

export function createTenantGuardExtension(options: TenantGuardOptions) {
  const logger = options.logger ?? new Logger('TenantGuard')

  return Prisma.defineExtension({
    name: 'tenant-guard',
    query: {
      $allOperations({ model, operation, args, query }) {
        if (!options.enabled) {
          return query(args)
        }

        try {
          const violations = inspectScope({
            model,
            operation,
            args,
            contextStoreId: options.tenantContext.getStoreId(),
          })

          if (violations.length > 0) {
            const requestId = options.tenantContext.getRequestId()

            for (const violation of violations) {
              logger.warn(
                `[tenant-scope] ${violation.model}.${violation.operation} — ` +
                  `${violation.kind}: ${violation.detail}` +
                  (requestId ? ` (request ${requestId})` : ''),
              )
            }
          }
        } catch (error) {
          // الفحص فشل — بنسجّل ونكمّل. الاستعلام أهم من الحارس.
          logger.error(
            `[tenant-scope] فشل الفحص لـ ${model ?? 'unknown'}.${operation}: ` +
              `${(error as Error).message}`,
          )
        }

        // args متمرّرة زي ما هي بالظبط، من غير أي تعديل
        return query(args)
      },
    },
  })
}
