import 'dotenv/config'
import { NestFactory } from '@nestjs/core'
import { ConfigService } from '@nestjs/config'
import { ValidationPipe, Logger } from '@nestjs/common'
import { AppModule } from './app.module'
import cookieParser from 'cookie-parser'
import type { AppConfig } from './common/config/configuration'

// Prisma بيرجّع BigInt، و JSON.stringify مابيعرفش يتعامل معاه.
// لازم يفضل هنا قبل أي serialization.
;(BigInt.prototype as any).toJSON = function () {
  return this.toString()
}

/**
 * يحوّل عنصر من قائمة CORS_ORIGINS لدالة مطابقة.
 * العنصر اللي بيبدأ بـ "*." معناه أي subdomain تحت الدومين ده،
 * وده اللي بيحافظ على سلوك الـ regex اللي كان مكتوب في الملف ده قبل كده.
 */
function buildOriginMatcher(pattern: string): (origin: string) => boolean {
  if (pattern.startsWith('*.')) {
    const suffix = pattern.slice(2)
    const escaped = suffix.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const regex = new RegExp(`^https?://([a-zA-Z0-9-]+\\.)+${escaped}$`)
    return (origin) => regex.test(origin)
  }

  return (origin) => origin === pattern
}

async function bootstrap() {
  const logger = new Logger('Bootstrap')

  // rawBody مطلوبة للتحقق من توقيع الـ webhooks في المراحل الجاية.
  const app = await NestFactory.create(AppModule, { rawBody: true })

  const config = app.get(ConfigService)
  const { port, corsOrigins, nodeEnv } =
    config.getOrThrow<AppConfig>('app')

  app.use(cookieParser())

  /**
   * التحقق من الـ DTOs.
   *
   * class-validator و class-transformer كانوا مثبتين في المشروع من غير
   * ما يتفعّلوا، يعني كل الـ DTOs الموجودة كانت شكلية. تفعيلهم هنا.
   *
   * forbidNonWhitelisted مقفولة عن قصد: whitelist بتشيل الحقول الزيادة
   * بصمت بدل ما ترفض الطلب كله، فمفيش طلب كان بينجح هيبدأ يفشل.
   *
   * ملاحظة: الـ routes اللي مكتوبة @Body() body: any مالهاش metatype،
   * فـ NestJS بيتخطاها تماماً — يعني أغلب الكود الحالي مش متأثر.
   */
  app.useGlobalPipes(
    new ValidationPipe({
      transform: true,
      whitelist: true,
      forbidNonWhitelisted: false,
      transformOptions: {
        enableImplicitConversion: false,
      },
    }),
  )

  const matchers = corsOrigins.map(buildOriginMatcher)

  app.enableCors({
    origin: (origin, callback) => {
      // الطلبات من غير Origin (server-to-server، curl، health checks)
      // مسموحة زي ما كانت بالظبط.
      if (!origin || matchers.some((matches) => matches(origin))) {
        callback(null, true)
      } else {
        callback(new Error('Blocked by CORS Policy (DartCoin Security)'))
      }
    },
    credentials: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS',
    allowedHeaders: [
      'Content-Type',
      'Authorization',
      'X-Register-Flow',
      'X-Register-Signature',
      'X-Device-Fingerprint',
    ],
  })

  app.setGlobalPrefix('api')

  // بيخلي onModuleDestroy تشتغل فعلاً عند SIGTERM — مهم لقفل اتصالات
  // Prisma بشكل نظيف.
  app.enableShutdownHooks()

  await app.listen(port)

  logger.log(`🚀 Server running on http://localhost:${port}/api [${nodeEnv}]`)
  logger.log(`🔓 CORS origins: ${corsOrigins.join(', ')}`)
}

bootstrap()
