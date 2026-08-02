import { Module } from '@nestjs/common'
import { TenantContextService } from './tenant-context.service'
import { TenantContextMiddleware } from './tenant-context.middleware'

/**
 * سياق المستأجر.
 *
 * الميدلوير بيتسجّل في main.ts، والـ extension بيتركّب في PrismaService.
 * الموديول ده بيوفّر الخدمة نفسها للحقن.
 *
 * @Global عشان PrismaService (اللي في موديول عام) محتاج يحقن
 * TenantContextService من غير دورة استيراد بين الموديولين.
 */
@Module({
  providers: [TenantContextService, TenantContextMiddleware],
  exports: [TenantContextService, TenantContextMiddleware],
})
export class TenantModule {}
