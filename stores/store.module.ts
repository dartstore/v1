import { Module } from '@nestjs/common'
import { StoreController } from './store.controller'
import { StorePublicController } from './store-public.controller'
import { StoreService } from './store.service'
import { ActiveStoreModule } from './active-store.module'

/**
 * ملاحظة: PrismaService كان مكتوب في providers هنا بالرغم من إن
 * PrismaModule معرّف @Global وبيصدّره أصلاً. النتيجة كانت instance
 * تانية من PrismaClient و connection pool زيادة على الداتابيز.
 * اتشال — الـ StoreService بياخد نفس الـ instance العامة زي باقي
 * الموديولات بالظبط.
 */
@Module({
  imports: [ActiveStoreModule],
  controllers: [StoreController, StorePublicController],
  providers: [StoreService],
  exports: [StoreService],
})
export class StoreModule {}
