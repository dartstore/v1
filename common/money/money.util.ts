import {
  getCurrency,
  minorUnitsPerMajor,
  normalizeCurrencyCode,
} from './currency.registry'
import {
  CurrencyCode,
  CurrencyMismatchError,
  Money,
  MoneyError,
  MoneyParseError,
} from './money.types'

/**
 * ══════════════════════════════════════════════════════════════════
 * أدوات الفلوس
 * ══════════════════════════════════════════════════════════════════
 *
 * دوال خالصة، من غير حالة ومن غير حقن اعتماديات.
 *
 * القواعد الملزمة (AI_RULES.md / docs/MONEY.md):
 *   1. الفلوس = عدد صحيح بالوحدات الصغرى + رمز عملة.
 *   2. ممنوع parseFloat أو Number على مبلغ نصي خارج الملف ده.
 *   3. العمليات الحسابية بين نفس العملة بس.
 *   4. تحويل الأس لصيغة البوابة مسؤولية الأدابتر، مش الدومين.
 */

/** الصيغة الوحيدة المقبولة للمبلغ النصي: أرقام إنجليزية، فاصلة عشرية واحدة */
const DECIMAL_PATTERN = /^-?\d+(\.\d+)?$/

/** ينشئ مبلغ من الوحدات الصغرى */
export function money(amountMinor: bigint | number, currency: string): Money {
  const normalized = normalizeCurrencyCode(currency)
  getCurrency(normalized) // بيرمي لو العملة مش مدعومة

  if (typeof amountMinor === 'number') {
    if (!Number.isSafeInteger(amountMinor)) {
      throw new MoneyError(
        `المبلغ لازم يكون عدد صحيح آمن بالوحدات الصغرى (استلمنا: ${amountMinor}).`,
      )
    }
    return Object.freeze({
      amountMinor: BigInt(amountMinor),
      currency: normalized,
    })
  }

  if (typeof amountMinor !== 'bigint') {
    throw new MoneyError(`المبلغ لازم يكون bigint أو number.`)
  }

  return Object.freeze({ amountMinor, currency: normalized })
}

export function zero(currency: string): Money {
  return money(0n, currency)
}

/**
 * يحوّل نص عشري لمبلغ.
 *
 * ده الحد الوحيد اللي بيدخل منه مدخل خارجي (API / بوابة) لنظام الفلوس،
 * فالتحقق هنا صارم عن قصد:
 *
 *   ❌ الصيغة الأسية (1e3)
 *   ❌ NaN / Infinity
 *   ❌ فواصل الآلاف (1,000)
 *   ❌ مسافات داخلية أو شرطة سفلية
 *   ❌ علامة + في الأول
 *   ❌ أرقام غير إنجليزية (٠١٢ / ۰۱۲)
 *   ❌ دقة أكتر من أس العملة — بيترفض مش بيتقص
 *
 * "-0.00" بيتحوّل لصفر عادي: bigint مافيهاش سالب-صفر أصلاً.
 */
export function parseDecimal(input: string, currency: string): Money {
  const normalizedCurrency = normalizeCurrencyCode(currency)
  const exponent = getCurrency(normalizedCurrency).exponent

  if (typeof input !== 'string') {
    throw new MoneyParseError(String(input), 'المدخل لازم يكون نص.')
  }

  const trimmed = input.trim()

  if (trimmed.length === 0) {
    throw new MoneyParseError(input, 'المدخل فاضي.')
  }

  if (!DECIMAL_PATTERN.test(trimmed)) {
    throw new MoneyParseError(
      input,
      'الصيغة المقبولة أرقام إنجليزية فقط بالشكل -?123 أو -?123.45 ' +
        '(ممنوع: الصيغة الأسية، الفواصل، المسافات الداخلية، علامة +، الأرقام العربية).',
    )
  }

  const negative = trimmed.startsWith('-')
  const unsigned = negative ? trimmed.slice(1) : trimmed
  const [integerPart, fractionPart = ''] = unsigned.split('.')

  if (fractionPart.length > exponent) {
    throw new MoneyParseError(
      input,
      `العملة ${normalizedCurrency} بتقبل ${exponent} خانة عشرية بحد أقصى ` +
        `(استلمنا ${fractionPart.length}). القص التلقائي ممنوع.`,
    )
  }

  const paddedFraction = fractionPart.padEnd(exponent, '0')
  const magnitude = BigInt(`${integerPart}${paddedFraction}`)

  return money(negative ? -magnitude : magnitude, normalizedCurrency)
}

/** يحوّل المبلغ لنص عشري بدقة العملة بالظبط (من غير فواصل آلاف) */
export function toDecimalString(value: Money): string {
  const exponent = getCurrency(value.currency).exponent

  if (exponent === 0) {
    return value.amountMinor.toString()
  }

  const negative = value.amountMinor < 0n
  const magnitude = negative ? -value.amountMinor : value.amountMinor
  const divisor = minorUnitsPerMajor(value.currency)

  const major = magnitude / divisor
  const minor = magnitude % divisor

  return `${negative ? '-' : ''}${major}.${minor
    .toString()
    .padStart(exponent, '0')}`
}

/** يعرض المبلغ بفواصل الآلاف ورمز العملة — للعرض فقط، مش للتخزين */
export function format(
  value: Money,
  options: { withSymbol?: boolean; locale?: string } = {},
): string {
  const { withSymbol = true, locale = 'en-US' } = options
  const definition = getCurrency(value.currency)
  const decimal = toDecimalString(value)

  const negative = decimal.startsWith('-')
  const unsigned = negative ? decimal.slice(1) : decimal
  const [integerPart, fractionPart] = unsigned.split('.')

  // التجميع بيتعمل على الجزء الصحيح بس، عشان الجزء العشري يفضل بدقته
  const grouped = new Intl.NumberFormat(locale, {
    useGrouping: true,
    maximumFractionDigits: 0,
  }).format(BigInt(integerPart) as unknown as number)

  const body = fractionPart ? `${grouped}.${fractionPart}` : grouped
  const signed = negative ? `-${body}` : body

  return withSymbol ? `${signed} ${definition.symbol}` : signed
}

export function assertSameCurrency(left: Money, right: Money): void {
  if (left.currency !== right.currency) {
    throw new CurrencyMismatchError(left.currency, right.currency)
  }
}

export function add(left: Money, right: Money): Money {
  assertSameCurrency(left, right)
  return money(left.amountMinor + right.amountMinor, left.currency)
}

export function subtract(left: Money, right: Money): Money {
  assertSameCurrency(left, right)
  return money(left.amountMinor - right.amountMinor, left.currency)
}

export function negate(value: Money): Money {
  return money(-value.amountMinor, value.currency)
}

export function absolute(value: Money): Money {
  return value.amountMinor < 0n ? negate(value) : value
}

/**
 * يضرب في عدد صحيح (مثلاً: سعر الوحدة × الكمية).
 *
 * الضرب في كسر عشري ممنوع عن قصد — ده بيجيب أخطاء تقريب. للنسب
 * والتقسيمات استخدم allocate.
 */
export function multiplyByInteger(
  value: Money,
  factor: bigint | number,
): Money {
  if (typeof factor === 'number' && !Number.isSafeInteger(factor)) {
    throw new MoneyError(
      `المعامل لازم يكون عدد صحيح (استلمنا: ${factor}). ` +
        `للنسب استخدم allocate بدل الضرب في كسر عشري.`,
    )
  }

  return money(value.amountMinor * BigInt(factor), value.currency)
}

/** يجمع قائمة مبالغ. القائمة الفاضية محتاجة تحديد العملة صراحةً. */
export function sum(values: readonly Money[], currency?: string): Money {
  if (values.length === 0) {
    if (!currency) {
      throw new MoneyError('sum على قائمة فاضية محتاج تحديد العملة.')
    }
    return zero(currency)
  }

  const target = currency ? normalizeCurrencyCode(currency) : values[0].currency

  return values.reduce<Money>((accumulator, value) => {
    assertSameCurrency(accumulator, value)
    return money(accumulator.amountMinor + value.amountMinor, target)
  }, zero(target))
}

export function compare(left: Money, right: Money): -1 | 0 | 1 {
  assertSameCurrency(left, right)
  if (left.amountMinor < right.amountMinor) return -1
  if (left.amountMinor > right.amountMinor) return 1
  return 0
}

export function equals(left: Money, right: Money): boolean {
  return (
    left.currency === right.currency && left.amountMinor === right.amountMinor
  )
}

export function isZero(value: Money): boolean {
  return value.amountMinor === 0n
}

export function isNegative(value: Money): boolean {
  return value.amountMinor < 0n
}

export function isPositive(value: Money): boolean {
  return value.amountMinor > 0n
}

export function min(left: Money, right: Money): Money {
  return compare(left, right) <= 0 ? left : right
}

export function max(left: Money, right: Money): Money {
  return compare(left, right) >= 0 ? left : right
}

/**
 * يقسّم مبلغ على أوزان من غير ما يضيع أو يخترع وحدة صغرى.
 *
 * الخوارزمية: أكبر باقي (largest remainder).
 *   1. كل طرف بياخد floor(المبلغ × وزنه ÷ مجموع الأوزان).
 *   2. الوحدات الفاضلة بتتوزّع على أصحاب أكبر بواقي، والتعادل بيتحسم
 *      بترتيب الفهرس عشان النتيجة تبقى حتمية.
 *
 * ضمانة أساسية: **مجموع الأجزاء = المبلغ الأصلي بالظبط، دايماً.**
 * (مُثبتة باختبار خصائص على آلاف الحالات العشوائية.)
 *
 * المبالغ السالبة (عكس استرداد) بتتعالج بالقيمة المطلقة وبعدين
 * بترجع الإشارة، عشان قسمة bigint بتقرّب ناحية الصفر وده كان
 * هيكسر التوزيع مع السوالب.
 *
 * ده اللي المرحلة 1b هتستخدمه في توزيع الاسترداد على المستفيدين.
 */
export function allocate(
  value: Money,
  weights: readonly (bigint | number)[],
): Money[] {
  if (weights.length === 0) {
    throw new MoneyError('allocate محتاج وزن واحد على الأقل.')
  }

  const normalizedWeights = weights.map((weight, index) => {
    // التحقق لازم يسبق التحويل: BigInt() بترمي RangeError خام على الكسور،
    // وده بيتخطى نظام الأخطاء بتاعنا ويوصل للمستدعي كخطأ غير متوقع.
    if (typeof weight === 'number' && !Number.isSafeInteger(weight)) {
      throw new MoneyError(
        `الوزن رقم ${index} لازم يكون عدد صحيح (استلمنا: ${weight}).`,
      )
    }

    if (typeof weight !== 'bigint' && typeof weight !== 'number') {
      throw new MoneyError(`الوزن رقم ${index} لازم يكون bigint أو number.`)
    }

    const asBigInt = typeof weight === 'bigint' ? weight : BigInt(weight)

    if (asBigInt < 0n) {
      throw new MoneyError(`الوزن رقم ${index} ماينفعش يكون سالب.`)
    }

    return asBigInt
  })

  const totalWeight = normalizedWeights.reduce((a, b) => a + b, 0n)

  if (totalWeight === 0n) {
    throw new MoneyError('مجموع الأوزان ماينفعش يكون صفر.')
  }

  const negative = value.amountMinor < 0n
  const magnitude = negative ? -value.amountMinor : value.amountMinor

  const shares: bigint[] = []
  const remainders: { index: number; remainder: bigint }[] = []
  let distributed = 0n

  for (let index = 0; index < normalizedWeights.length; index += 1) {
    const numerator = magnitude * normalizedWeights[index]
    const share = numerator / totalWeight
    shares.push(share)
    remainders.push({ index, remainder: numerator % totalWeight })
    distributed += share
  }

  let leftover = magnitude - distributed

  remainders.sort((a, b) => {
    if (a.remainder > b.remainder) return -1
    if (a.remainder < b.remainder) return 1
    return a.index - b.index // تعادل → الفهرس الأقل الأول (حتمية)
  })

  for (let position = 0; leftover > 0n; position += 1, leftover -= 1n) {
    shares[remainders[position % remainders.length].index] += 1n
  }

  return shares.map((share) => money(negative ? -share : share, value.currency))
}

/** يقسّم المبلغ على أجزاء متساوية بنفس ضمانة عدم الضياع */
export function allocateEvenly(value: Money, parts: number): Money[] {
  if (!Number.isSafeInteger(parts) || parts < 1) {
    throw new MoneyError(
      `عدد الأجزاء لازم يكون عدد صحيح موجب (استلمنا: ${parts}).`,
    )
  }

  return allocate(value, new Array<bigint>(parts).fill(1n))
}

/** الوحدات الصغرى كنص — للبوابات اللي بتقبل نص */
export function toMinorUnitString(value: Money): string {
  return value.amountMinor.toString()
}

/**
 * الوحدات الصغرى كـ number — لمعظم البوابات (Stripe, Paymob, Moyasar).
 *
 * بيرفض التحويل لو المبلغ أكبر من المدى الآمن بدل ما يفقد دقة بصمت.
 */
export function toGatewayInteger(value: Money): number {
  const asNumber = Number(value.amountMinor)

  if (!Number.isSafeInteger(asNumber)) {
    throw new MoneyError(
      `المبلغ ${value.amountMinor} أكبر من إن يتحوّل لـ number بأمان. ` +
        `استخدم toMinorUnitString مع البوابات اللي بتقبل نص.`,
    )
  }

  return asNumber
}

/** شكل المبلغ في JSON — bigint مابتتسلسلش بشكل افتراضي */
export function serialize(value: Money): {
  amountMinor: string
  currency: CurrencyCode
} {
  return { amountMinor: value.amountMinor.toString(), currency: value.currency }
}

export function deserialize(raw: {
  amountMinor: string
  currency: string
}): Money {
  if (!/^-?\d+$/.test(raw.amountMinor)) {
    throw new MoneyParseError(
      raw.amountMinor,
      'المبلغ بالوحدات الصغرى لازم يكون عدد صحيح.',
    )
  }
  return money(BigInt(raw.amountMinor), raw.currency)
}
