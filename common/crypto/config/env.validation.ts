import { plainToInstance } from 'class-transformer'
import {
  IsEnum,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Max,
  Min,
  validateSync,
} from 'class-validator'

/**
 * التحقق من متغيرات البيئة وقت الإقلاع.
 *
 * الفكرة: أي متغير ناقص أو غلط لازم يوقّف السيرفر فوراً بخطأ واضح،
 * مش يفضل شغال ويقع بعدين عند أول استخدام. ده اللي بيخلينا نقدر
 * نشيل الـ fallback secrets المكتوبة في الكود بأمان.
 *
 * ملاحظة مقصودة: JWT_SECRET و FLOW_SECRET بيتحقق منهم كنص غير فارغ بس،
 * من غير حد أدنى للطول، عشان مانكسرش أي بيئة شغالة حالياً. لو الطول
 * أقل من 32 حرف بنطبع تحذير من غير ما نمنع الإقلاع.
 */

export enum NodeEnv {
  Development = 'development',
  Production = 'production',
  Test = 'test',
}

export class EnvironmentVariables {
  @IsOptional()
  @IsEnum(NodeEnv)
  NODE_ENV: NodeEnv = NodeEnv.Development

  @IsOptional()
  @IsInt()
  @Min(1)
  @Max(65535)
  PORT: number = 4000

  @IsString()
  @IsNotEmpty({ message: 'DATABASE_URL مطلوب' })
  DATABASE_URL!: string

  @IsString()
  @IsNotEmpty({ message: 'JWT_SECRET مطلوب — مفيش fallback بعد دلوقتي' })
  JWT_SECRET!: string

  @IsString()
  @IsNotEmpty({ message: 'FLOW_SECRET مطلوب — مفيش fallback بعد دلوقتي' })
  FLOW_SECRET!: string

  @IsString()
  @IsNotEmpty({ message: 'PAYMENT_ENCRYPTION_KEY مطلوب' })
  PAYMENT_ENCRYPTION_KEY!: string

  @IsOptional()
  @IsInt()
  @Min(1)
  PAYMENT_ENCRYPTION_KEY_VERSION: number = 1

  @IsOptional()
  @IsString()
  PAYMENT_ENCRYPTION_KEY_PREVIOUS?: string

  @IsOptional()
  @IsInt()
  @Min(1)
  PAYMENT_ENCRYPTION_KEY_PREVIOUS_VERSION?: number

  @IsOptional()
  @IsString()
  CORS_ORIGINS: string = 'http://localhost:3000,*.localhost:3000'
}

/** الحد الأدنى المفضل لطول الأسرار النصية — تحذير فقط، مش منع إقلاع */
const RECOMMENDED_SECRET_LENGTH = 32

/** الطول المطلوب لمفتاح التشفير بعد فك الـ base64 */
const REQUIRED_KEY_BYTES = 32

function assertBase64Key(name: string, value: string): void {
  let decoded: Buffer

  try {
    decoded = Buffer.from(value, 'base64')
  } catch {
    throw new Error(`${name} مش base64 صالح.`)
  }

  // Buffer.from لا يرمي خطأ على مدخلات غير صالحة، بيتجاهل الحروف الغلط،
  // فبنتأكد من الطول الناتج بدل ما نعتمد على استثناء.
  if (decoded.length !== REQUIRED_KEY_BYTES) {
    throw new Error(
      `${name} لازم يكون ${REQUIRED_KEY_BYTES} byte بعد فك الـ base64 ` +
        `(الناتج الحالي ${decoded.length} byte). ` +
        `ولّده بالأمر: openssl rand -base64 32`,
    )
  }
}

function warnIfWeak(name: string, value: string): void {
  if (value.length < RECOMMENDED_SECRET_LENGTH) {
    // eslint-disable-next-line no-console
    console.warn(
      `⚠️  ${name} طوله ${value.length} حرف — يُفضّل ${RECOMMENDED_SECRET_LENGTH} حرف على الأقل. ` +
        `ولّد واحد أقوى بالأمر: openssl rand -base64 48`,
    )
  }
}

/**
 * تُستدعى من ConfigModule.forRoot({ validate }).
 * بترجع الكائن بعد التحويل عشان الأنواع (زي PORT) تبقى مضبوطة.
 */
export function validateEnv(
  config: Record<string, unknown>,
): EnvironmentVariables {
  const validated = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
    excludeExtraneousValues: false,
  })

  const errors = validateSync(validated, {
    skipMissingProperties: false,
    whitelist: false,
  })

  if (errors.length > 0) {
    const details = errors
      .map((error) => {
        const messages = Object.values(error.constraints ?? {}).join(', ')
        return `  • ${error.property}: ${messages}`
      })
      .join('\n')

    throw new Error(
      `❌ إعدادات البيئة غير صالحة — السيرفر مش هيقوم:\n${details}\n\n` +
        `راجع backend/.env.example`,
    )
  }

  assertBase64Key('PAYMENT_ENCRYPTION_KEY', validated.PAYMENT_ENCRYPTION_KEY)

  if (validated.PAYMENT_ENCRYPTION_KEY_PREVIOUS) {
    assertBase64Key(
      'PAYMENT_ENCRYPTION_KEY_PREVIOUS',
      validated.PAYMENT_ENCRYPTION_KEY_PREVIOUS,
    )

    if (!validated.PAYMENT_ENCRYPTION_KEY_PREVIOUS_VERSION) {
      throw new Error(
        'PAYMENT_ENCRYPTION_KEY_PREVIOUS متظبط من غير ' +
          'PAYMENT_ENCRYPTION_KEY_PREVIOUS_VERSION — لازم الاتنين مع بعض.',
      )
    }

    if (
      validated.PAYMENT_ENCRYPTION_KEY_PREVIOUS_VERSION ===
      validated.PAYMENT_ENCRYPTION_KEY_VERSION
    ) {
      throw new Error(
        'PAYMENT_ENCRYPTION_KEY_PREVIOUS_VERSION لازم يكون مختلف عن ' +
          'PAYMENT_ENCRYPTION_KEY_VERSION.',
      )
    }
  }

  warnIfWeak('JWT_SECRET', validated.JWT_SECRET)
  warnIfWeak('FLOW_SECRET', validated.FLOW_SECRET)

  return validated
}
