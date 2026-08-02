import { CurrencyCode, UnknownCurrencyError } from './money.types'

/**
 * ══════════════════════════════════════════════════════════════════
 * سجل العملات — المصدر الوحيد للأس العشري
 * ══════════════════════════════════════════════════════════════════
 *
 * الأس (exponent) هو عدد الخانات العشرية حسب ISO-4217، وهو اللي
 * بيحدد التحويل بين الوحدة الكبرى والصغرى.
 *
 * ⚠️ ثلاث فئات، وكل واحدة كسرت أنظمة دفع حقيقية:
 *   أس 0 → JPY, KRW      (مفيش خانات عشرية خالص)
 *   أس 2 → USD, EGP, SAR (الحالة الشائعة)
 *   أس 3 → KWD, BHD, OMR (تلات خانات — Decimal(12,2) بيفقد بيانات هنا)
 *
 * أي أدابتر بوابة في المرحلة 1b لازم ياخد الأس من هنا. ممنوع أي كود
 * يفترض إن ×100 هو التحويل الصح.
 */
export interface CurrencyDefinition {
  readonly code: CurrencyCode
  readonly exponent: 0 | 2 | 3
  readonly symbol: string
  readonly nameEn: string
  readonly nameAr: string
}

const DEFINITIONS: readonly CurrencyDefinition[] = [
  // ── عملات بدون خانات عشرية (أس 0) ─────────────────────────────
  { code: 'JPY', exponent: 0, symbol: '¥',    nameEn: 'Japanese Yen',              nameAr: 'ين ياباني' },
  { code: 'KRW', exponent: 0, symbol: '₩',    nameEn: 'South Korean Won',          nameAr: 'وون كوري' },
  { code: 'VND', exponent: 0, symbol: '₫',    nameEn: 'Vietnamese Dong',           nameAr: 'دونغ فيتنامي' },
  { code: 'CLP', exponent: 0, symbol: '$',    nameEn: 'Chilean Peso',              nameAr: 'بيزو تشيلي' },
  { code: 'ISK', exponent: 0, symbol: 'kr',   nameEn: 'Icelandic Krona',           nameAr: 'كرونا آيسلندية' },
  { code: 'XAF', exponent: 0, symbol: 'FCFA', nameEn: 'Central African CFA Franc', nameAr: 'فرنك وسط أفريقي' },
  { code: 'XOF', exponent: 0, symbol: 'CFA',  nameEn: 'West African CFA Franc',    nameAr: 'فرنك غرب أفريقي' },

  // ── عملات بتلات خانات عشرية (أس 3) ────────────────────────────
  { code: 'KWD', exponent: 3, symbol: 'د.ك', nameEn: 'Kuwaiti Dinar',   nameAr: 'دينار كويتي' },
  { code: 'BHD', exponent: 3, symbol: 'د.ب', nameEn: 'Bahraini Dinar',  nameAr: 'دينار بحريني' },
  { code: 'OMR', exponent: 3, symbol: 'ر.ع', nameEn: 'Omani Rial',      nameAr: 'ريال عماني' },
  { code: 'JOD', exponent: 3, symbol: 'د.أ', nameEn: 'Jordanian Dinar', nameAr: 'دينار أردني' },
  { code: 'TND', exponent: 3, symbol: 'د.ت', nameEn: 'Tunisian Dinar',  nameAr: 'دينار تونسي' },
  { code: 'IQD', exponent: 3, symbol: 'د.ع', nameEn: 'Iraqi Dinar',     nameAr: 'دينار عراقي' },
  { code: 'LYD', exponent: 3, symbol: 'د.ل', nameEn: 'Libyan Dinar',    nameAr: 'دينار ليبي' },

  // ── عملات بخانتين عشريتين (أس 2) ──────────────────────────────
  { code: 'USD', exponent: 2, symbol: '$',   nameEn: 'US Dollar',          nameAr: 'دولار أمريكي' },
  { code: 'EUR', exponent: 2, symbol: '€',   nameEn: 'Euro',               nameAr: 'يورو' },
  { code: 'GBP', exponent: 2, symbol: '£',   nameEn: 'British Pound',      nameAr: 'جنيه إسترليني' },
  { code: 'EGP', exponent: 2, symbol: 'ج.م', nameEn: 'Egyptian Pound',     nameAr: 'جنيه مصري' },
  { code: 'SAR', exponent: 2, symbol: 'ر.س', nameEn: 'Saudi Riyal',        nameAr: 'ريال سعودي' },
  { code: 'AED', exponent: 2, symbol: 'د.إ', nameEn: 'UAE Dirham',         nameAr: 'درهم إماراتي' },
  { code: 'QAR', exponent: 2, symbol: 'ر.ق', nameEn: 'Qatari Riyal',       nameAr: 'ريال قطري' },
  { code: 'MAD', exponent: 2, symbol: 'د.م', nameEn: 'Moroccan Dirham',    nameAr: 'درهم مغربي' },
  { code: 'DZD', exponent: 2, symbol: 'د.ج', nameEn: 'Algerian Dinar',     nameAr: 'دينار جزائري' },
  { code: 'LBP', exponent: 2, symbol: 'ل.ل', nameEn: 'Lebanese Pound',     nameAr: 'ليرة لبنانية' },
  { code: 'TRY', exponent: 2, symbol: '₺',   nameEn: 'Turkish Lira',       nameAr: 'ليرة تركية' },
  { code: 'PKR', exponent: 2, symbol: '₨',   nameEn: 'Pakistani Rupee',    nameAr: 'روبية باكستانية' },
  { code: 'INR', exponent: 2, symbol: '₹',   nameEn: 'Indian Rupee',       nameAr: 'روبية هندية' },
  { code: 'CAD', exponent: 2, symbol: '$',   nameEn: 'Canadian Dollar',    nameAr: 'دولار كندي' },
  { code: 'AUD', exponent: 2, symbol: '$',   nameEn: 'Australian Dollar',  nameAr: 'دولار أسترالي' },
  { code: 'CHF', exponent: 2, symbol: 'Fr',  nameEn: 'Swiss Franc',        nameAr: 'فرنك سويسري' },
  { code: 'SEK', exponent: 2, symbol: 'kr',  nameEn: 'Swedish Krona',      nameAr: 'كرونا سويدية' },
  { code: 'NOK', exponent: 2, symbol: 'kr',  nameEn: 'Norwegian Krone',    nameAr: 'كرونة نرويجية' },
  { code: 'DKK', exponent: 2, symbol: 'kr',  nameEn: 'Danish Krone',       nameAr: 'كرونة دنماركية' },
  { code: 'PLN', exponent: 2, symbol: 'zł',  nameEn: 'Polish Zloty',       nameAr: 'زلوتي بولندي' },
  { code: 'ZAR', exponent: 2, symbol: 'R',   nameEn: 'South African Rand', nameAr: 'راند جنوب أفريقي' },
  { code: 'NGN', exponent: 2, symbol: '₦',   nameEn: 'Nigerian Naira',     nameAr: 'نايرا نيجيرية' },
  { code: 'KES', exponent: 2, symbol: 'KSh', nameEn: 'Kenyan Shilling',    nameAr: 'شلن كيني' },
  { code: 'CNY', exponent: 2, symbol: '¥',   nameEn: 'Chinese Yuan',       nameAr: 'يوان صيني' },
  { code: 'SGD', exponent: 2, symbol: '$',   nameEn: 'Singapore Dollar',   nameAr: 'دولار سنغافوري' },
  { code: 'MYR', exponent: 2, symbol: 'RM',  nameEn: 'Malaysian Ringgit',  nameAr: 'رينغيت ماليزي' },
  { code: 'IDR', exponent: 2, symbol: 'Rp',  nameEn: 'Indonesian Rupiah',  nameAr: 'روبية إندونيسية' },
  { code: 'BRL', exponent: 2, symbol: 'R$',  nameEn: 'Brazilian Real',     nameAr: 'ريال برازيلي' },
  { code: 'MXN', exponent: 2, symbol: '$',   nameEn: 'Mexican Peso',       nameAr: 'بيزو مكسيكي' },
]

const REGISTRY: ReadonlyMap<CurrencyCode, CurrencyDefinition> = new Map(
  DEFINITIONS.map((definition) => [definition.code, definition]),
)

const CURRENCY_CODE_PATTERN = /^[A-Z]{3}$/

/** يوحّد شكل رمز العملة (يشيل الفراغات ويحوّل لحروف كبيرة) */
export function normalizeCurrencyCode(raw: string): CurrencyCode {
  if (typeof raw !== 'string') {
    throw new UnknownCurrencyError(String(raw))
  }

  const normalized = raw.trim().toUpperCase()

  if (!CURRENCY_CODE_PATTERN.test(normalized)) {
    throw new UnknownCurrencyError(raw)
  }

  return normalized
}

/** يرجّع تعريف العملة، أو يرمي لو مش مدعومة */
export function getCurrency(code: string): CurrencyDefinition {
  const normalized = normalizeCurrencyCode(code)
  const definition = REGISTRY.get(normalized)

  if (!definition) {
    throw new UnknownCurrencyError(normalized)
  }

  return definition
}

export function isSupportedCurrency(code: string): boolean {
  try {
    getCurrency(code)
    return true
  } catch {
    return false
  }
}

/** عدد الخانات العشرية للعملة */
export function getExponent(code: string): number {
  return getCurrency(code).exponent
}

/** كام وحدة صغرى في الوحدة الكبرى (10^أس) */
export function minorUnitsPerMajor(code: string): bigint {
  return 10n ** BigInt(getCurrency(code).exponent)
}

/** كل العملات المدعومة — للواجهات ولقوائم الاختيار */
export function listCurrencies(): readonly CurrencyDefinition[] {
  return DEFINITIONS
}
