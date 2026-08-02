import { Injectable } from '@nestjs/common'
import { AsyncLocalStorage } from 'async_hooks'
import type { Mode } from '../money/money.types'

/**
 * سياق المستأجر للطلب الحالي.
 *
 * ⚠️ متاح جزئياً في المرحلة 1a. الميدلوير بيملأ اللي يقدر عليه من
 * الطلب، لكن حل المتجر النشط بيحصل في الـ Guards بعد الميدلوير، فمعظم
 * الطلبات هيبقى فيها storeId = null.
 *
 * ده مقبول لأن الاستخدام الوحيد في 1a هو التبليغ. الحل الكامل بييجي
 * في المرحلة 1b مع ActiveStoreGuard.
 */
export interface TenantContext {
  storeId: string | null
  mode: Mode
  actor: string | null
  requestId: string | null
}

@Injectable()
export class TenantContextService {
  private readonly storage = new AsyncLocalStorage<TenantContext>()

  /** يشغّل دالة جوه سياق مستأجر */
  run<T>(context: TenantContext, callback: () => T): T {
    return this.storage.run(context, callback)
  }

  /** السياق الحالي، أو undefined لو إحنا برّه أي طلب (مهمة مجدولة مثلاً) */
  get(): TenantContext | undefined {
    return this.storage.getStore()
  }

  getStoreId(): string | null {
    return this.storage.getStore()?.storeId ?? null
  }

  /** الوضع الحالي، والافتراضي live لو مفيش سياق */
  getMode(): Mode {
    return this.storage.getStore()?.mode ?? 'live'
  }

  getRequestId(): string | null {
    return this.storage.getStore()?.requestId ?? null
  }

  /**
   * يحدّث معرّف المتجر بعد ما الـ Guard يحلّه.
   *
   * الميدلوير بيشتغل قبل الـ Guards، فالمتجر مش معروف وقت فتح السياق.
   * التعديل هنا بيغيّر نفس الكائن اللي جوه AsyncLocalStorage، وده آمن
   * لأنه محصور في الطلب الحالي.
   */
  setStoreId(storeId: string | null): void {
    const context = this.storage.getStore()
    if (context) context.storeId = storeId
  }

  setMode(mode: Mode): void {
    const context = this.storage.getStore()
    if (context) context.mode = mode
  }
}
