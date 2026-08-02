import { Injectable, OnModuleInit, OnModuleDestroy } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';
import { EventEmitter2 } from '@nestjs/event-emitter';
import { ConfigService } from '@nestjs/config';
import { TenantContextService } from '../common/tenant/tenant-context.service';
import { createTenantGuardExtension } from '../common/tenant/tenant-guard.extension';
import type { TenantConfig } from '../common/config/configuration';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  /**
   * كاش للعميل الموسّع بحارس العزل.
   *
   * unknown مش النوع المستنتج: $extends بيرجّع نوع معقّد، وتخزينه في
   * حقل معرّف بـ ReferenceType بيعمل دورة استنتاج في TypeScript.
   * التحويل بيحصل في guarded() نفسها، فالمستدعي بياخد النوع الصح.
   */
  private guardedCache: unknown = null

  constructor(
    private eventEmitter: EventEmitter2,
    private readonly config: ConfigService,
    private readonly tenantContext: TenantContextService,
  ) {
    super()
  }

  async onModuleInit() {
    await this.$connect()
    console.log('✅ Database connected successfully!')
  }

  async onModuleDestroy() {
    await this.$disconnect()
  }

  /**
   * عميل Prisma مع حارس عزل المستأجرين.
   *
   * الحارس **تبليغ فقط**: بيسجّل تحذير لو استعلام على موديل مسجّل في
   * tenant-scoped-models مش مقيّد بـ store_id و mode. مابيعدّلش الاستعلام،
   * ومابيضيفش شروط، ومابيمنعش أي عملية.
   *
   * ⚠️ ده مسار **اختياري بالكامل**. كل الخدمات الموجودة في المشروع
   * بتستخدم `this` مباشرةً زي ما هي بالظبط، ومفيش أي تغيير في سلوكها
   * ولا في أنواعها. خدمات المرحلة 1b هي اللي هتستخدم guarded() صراحةً.
   *
   * السبب في إنه اختياري: $extends بيرجّع عميل بنوع مختلف، فلو استبدلنا
   * العميل الأساسي كان التغيير هيمتد لكل خدمة في المشروع.
   */
  guarded() {
    if (!this.guardedCache) {
      this.guardedCache = this.buildGuardedClient()
    }
    return this.guardedCache as ReturnType<PrismaService['buildGuardedClient']>
  }

  private buildGuardedClient() {
    const tenant = this.config.get<TenantConfig>('tenant')

    return this.$extends(
      createTenantGuardExtension({
        enabled: tenant?.guardEnabled ?? false,
        tenantContext: this.tenantContext,
      }),
    )
  }

  /**
   * ✅ استدعى الدالة دى قبل أى delete على devices
   */
  async deleteDevice(deviceId: bigint) {
    const device = await this.devices.findFirst({
      where: { id: deviceId },
      select: { id: true, user_id: true }
    })

    const result = await this.devices.delete({
      where: { id: deviceId }
    })

    if (device) {
      this.eventEmitter.emit('device.deleted', {
        deviceId: device.id.toString(),
        userId: device.user_id.toString()
      })
    }

    return result
  }

  async deleteManyDevices(where: any) {
    const devices = await this.devices.findMany({
      where,
      select: { id: true, user_id: true }
    })

    const result = await this.devices.deleteMany({ where })

    for (const device of devices) {
      this.eventEmitter.emit('device.deleted', {
        deviceId: device.id.toString(),
        userId: device.user_id.toString()
      })
    }

    return result
  }
}
