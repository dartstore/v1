import { Module } from '@nestjs/common'
import { IdReservationService } from './id-reservation.service'

/**
 * حجز المعرّفات.
 *
 * مالوش مستهلك في المرحلة 1a — أول مستهلك هيبقى PaymentAccount في 1b.
 * موجود دلوقتي عشان الآلية تكون متغطّية باختبارات قبل ما أول نص مشفّر
 * مربوط بـ AAD يتكتب.
 *
 * PrismaModule معرّف @Global فمش محتاج يتستورد هنا.
 */
@Module({
  providers: [IdReservationService],
  exports: [IdReservationService],
})
export class IdsModule {}
