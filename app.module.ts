import { Module } from '@nestjs/common'
import { ConfigModule } from '@nestjs/config'
import { ScheduleModule } from '@nestjs/schedule'
import { AppController } from './app.controller'
import { AppService } from './app.service'
import { PrismaModule } from './prisma/prisma.module'
import { AuthModule } from './auth/auth.module'
import { WalletModule } from './wallet/wallet.module'
import { DevicesModule } from './devices/devices.module'
import { NotificationsModule } from './notifications/notifications.module'
import { EventEmitterModule } from '@nestjs/event-emitter'
import { StoreModule } from './stores/store.module'
import { ProductModule } from './stores/products/product.module'
import { OrderModule } from './stores/orders/order.module'
import { CollectionsModule } from './stores/collections/collections.module'
import { UploadsModule } from './uploads/uploads.module'
import { ActiveStoreModule } from './stores/active-store.module'
import { CryptoModule } from './common/crypto/crypto.module'
import { configurationLoaders } from './common/config/configuration'
import { validateEnv } from './common/config/env.validation'

@Module({
  imports: [
    // لازم تكون الأولى — باقي الموديولات بتعتمد على الإعدادات.
    // validate بتوقّف السيرفر فوراً لو في متغير بيئة ناقص أو غلط.
    ConfigModule.forRoot({
      isGlobal: true,
      cache: true,
      load: configurationLoaders,
      validate: validateEnv,
    }),

    // متثبتة في المشروع من قبل من غير ما تتسجل. مسجّلة هنا من غير أي
    // مهام مجدولة في المرحلة صفر — أول مهمة هتيجي مع الـ Outbox في
    // المرحلة الأولى.
    ScheduleModule.forRoot(),

    // أساس التشفير. تسجيله بيخلي PAYMENT_ENCRYPTION_KEY شرط للإقلاع.
    CryptoModule,

    PrismaModule,
    AuthModule,
    WalletModule,
    DevicesModule,
    NotificationsModule,
    EventEmitterModule.forRoot(),
    CollectionsModule,
    OrderModule,
    ProductModule,
    StoreModule,
    UploadsModule,
    ActiveStoreModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
