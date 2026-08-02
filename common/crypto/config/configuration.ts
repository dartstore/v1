import { registerAs } from '@nestjs/config'

/**
 * إعدادات مقسّمة على ثلاث مساحات (namespaces):
 *   app       → المنفذ، البيئة، الـ CORS
 *   security  → أسرار التوقيع
 *   payments  → مفاتيح التشفير
 *
 * الاستخدام:
 *   configService.getOrThrow<string>('security.jwtSecret')
 *   configService.get<AppConfig>('app')
 */

/** يفصل قائمة مفصولة بفواصل ويشيل الفراغات والعناصر الفاضية */
function parseList(raw: string | undefined): string[] {
  if (!raw) return []
  return raw
    .split(',')
    .map((item) => item.trim())
    .filter((item) => item.length > 0)
}

export interface AppConfig {
  nodeEnv: string
  isProduction: boolean
  port: number
  /**
   * قائمة الـ origins المسموح بها. العنصر اللي بيبدأ بـ "*." معناه
   * أي subdomain تحت الدومين ده (بيتحوّل لـ regex في main.ts).
   */
  corsOrigins: string[]
}

export interface SecurityConfig {
  jwtSecret: string
  flowSecret: string
}

export interface PaymentsConfig {
  /** المفتاح الجذر الحالي (KEK) — base64، 32 byte بعد الفك */
  encryptionKey: string
  /** رقم النسخة اللي بتتكتب جوه كل envelope جديد */
  encryptionKeyVersion: number
  /** مفتاح متقاعد أثناء التدوير — عشان النصوص القديمة تفضل قابلة للفك */
  previousEncryptionKey?: string
  previousEncryptionKeyVersion?: number
}

export const appConfig = registerAs<AppConfig>('app', () => ({
  nodeEnv: process.env.NODE_ENV ?? 'development',
  isProduction: process.env.NODE_ENV === 'production',
  port: parseInt(process.env.PORT ?? '4000', 10),
  corsOrigins: parseList(
    process.env.CORS_ORIGINS ?? 'http://localhost:3000,*.localhost:3000',
  ),
}))

export const securityConfig = registerAs<SecurityConfig>('security', () => ({
  jwtSecret: process.env.JWT_SECRET as string,
  flowSecret: process.env.FLOW_SECRET as string,
}))

export const paymentsConfig = registerAs<PaymentsConfig>('payments', () => ({
  encryptionKey: process.env.PAYMENT_ENCRYPTION_KEY as string,
  encryptionKeyVersion: parseInt(
    process.env.PAYMENT_ENCRYPTION_KEY_VERSION ?? '1',
    10,
  ),
  previousEncryptionKey: process.env.PAYMENT_ENCRYPTION_KEY_PREVIOUS,
  previousEncryptionKeyVersion: process.env
    .PAYMENT_ENCRYPTION_KEY_PREVIOUS_VERSION
    ? parseInt(process.env.PAYMENT_ENCRYPTION_KEY_PREVIOUS_VERSION, 10)
    : undefined,
}))

export const configurationLoaders = [appConfig, securityConfig, paymentsConfig]
