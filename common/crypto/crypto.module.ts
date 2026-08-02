import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { EncryptionService } from './encryption.service'
import { EnvKeyProvider } from './env-key.provider'
import { KEY_PROVIDER } from './key-provider.interface'
import { StoreKeyService } from './store-key.service'

/**
 * أساس التشفير في المشروع.
 *
 * بيصدّر ثلاث حاجات:
 *   KEY_PROVIDER      → مصدر المفاتيح الجذرية (env دلوقتي، KMS بعدين)
 *   EncryptionService → تشفير عام على مستوى المنصة
 *   StoreKeyService   → تشفير معزول لكل متجر (الاستخدام الأساسي للدفع)
 *
 * مالوش مستهلك في Production لسه — أول مستهلك هيبقى PaymentAccount في
 * المرحلة الأولى. اتقفل شكل الـ envelope واتغطّى باختبارات قبل ما أول
 * بيانات حساسة تتخزّن، وده الغرض من وجوده في المرحلة صفر.
 *
 * ⚠️ تسجيل الموديول ده بيخلي PAYMENT_ENCRYPTION_KEY شرط للإقلاع لأول مرة.
 */
@Module({
  imports: [ConfigModule],
  providers: [
    {
      provide: KEY_PROVIDER,
      useClass: EnvKeyProvider,
    },
    EncryptionService,
    StoreKeyService,
  ],
  exports: [KEY_PROVIDER, EncryptionService, StoreKeyService],
})
export class CryptoModule {}
