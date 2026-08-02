import { Injectable, OnModuleInit } from '@nestjs/common'
import { ConfigService } from '@nestjs/config'
import type { PaymentsConfig } from '../config/configuration'
import { KeyProvider } from './key-provider.interface'

/**
 * مزوّد مفاتيح مصدره متغيرات البيئة.
 *
 * بيدعم مفتاحين: الحالي (بيتشفّر بيه) والمتقاعد (بيتفك بيه بس).
 * ده اللي بيخلي تدوير المفتاح ممكن من غير ما نعيد تشفير كل الداتا
 * في لحظة واحدة.
 *
 * المفاتيح بتتقرأ مرة واحدة وقت الإقلاع وبتفضل في الميموري.
 * التحقق من الطول بيحصل في env.validation.ts، وبنتحقق تاني هنا
 * كخط دفاع أخير.
 */
@Injectable()
export class EnvKeyProvider implements KeyProvider, OnModuleInit {
  private readonly keys = new Map<number, Buffer>()
  private current!: number

  constructor(private readonly config: ConfigService) {}

  onModuleInit(): void {
    const payments = this.config.getOrThrow<PaymentsConfig>('payments')

    this.current = payments.encryptionKeyVersion
    this.keys.set(
      payments.encryptionKeyVersion,
      this.decodeKey(payments.encryptionKey, 'PAYMENT_ENCRYPTION_KEY'),
    )

    if (
      payments.previousEncryptionKey &&
      payments.previousEncryptionKeyVersion
    ) {
      this.keys.set(
        payments.previousEncryptionKeyVersion,
        this.decodeKey(
          payments.previousEncryptionKey,
          'PAYMENT_ENCRYPTION_KEY_PREVIOUS',
        ),
      )
    }
  }

  currentVersion(): number {
    if (this.current === undefined) {
      throw new Error(
        'EnvKeyProvider لسه ماتهيّأش — onModuleInit ماتنفذش. ' +
          'تأكد إن CryptoModule متسجل في الـ module tree.',
      )
    }
    return this.current
  }

  getKek(version: number): Buffer {
    const key = this.keys.get(version)

    if (!key) {
      throw new Error(
        `مفتاح التشفير نسخة ${version} مش متاح في البيئة الحالية. ` +
          `في نص مشفّر بالنسخة دي محتاج المفتاح بتاعها. ` +
          `ظبّط PAYMENT_ENCRYPTION_KEY_PREVIOUS و ` +
          `PAYMENT_ENCRYPTION_KEY_PREVIOUS_VERSION=${version}`,
      )
    }

    return key
  }

  private decodeKey(raw: string, name: string): Buffer {
    const decoded = Buffer.from(raw, 'base64')

    if (decoded.length !== 32) {
      throw new Error(
        `${name} لازم يكون 32 byte بعد فك الـ base64 ` +
          `(حالياً ${decoded.length} byte).`,
      )
    }

    return decoded
  }
}
