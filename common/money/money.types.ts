/**
 * ══════════════════════════════════════════════════════════════════
 * مفردات الفلوس
 * ══════════════════════════════════════════════════════════════════
 *
 * القاعدة الأساسية في المشروع (docs/MONEY.md):
 * الفلوس بتتخزّن كعدد صحيح بالوحدات الصغرى + رمز العملة.
 * ممنوع float، وممنوع Decimal في أي حاجة ليها علاقة بالدفع أو الدفتر.
 */

/**
 * وضع التشغيل.
 *
 * مطابق بنيوياً لـ CryptoMode في common/crypto — الاتنين نفس القيم.
 * متكرر عن قصد عشان مانخليش موديول الفلوس يعتمد على موديول التشفير؛
 * الاتنين طبقات أساس مستقلة.
 */
export type Mode = 'test' | 'live'

/** رمز ISO-4217 بثلاث حروف كبيرة */
export type CurrencyCode = string

/**
 * مبلغ مالي.
 *
 * amountMinor بالوحدات الصغرى للعملة:
 *   USD 10.50 → 1050n   (أس 2)
 *   KWD 10.500 → 10500n (أس 3)
 *   JPY 1000  → 1000n   (أس 0)
 *
 * bigint مش number: مافيش أي احتمال لخطأ فاصلة عائمة، والمدى غير
 * محدود، وبيتوافق مع BigInt المستخدم في مفاتيح Prisma.
 *
 * الكائن مجمّد (frozen) — المبالغ قيم غير قابلة للتغيير.
 */
export interface Money {
  readonly amountMinor: bigint
  readonly currency: CurrencyCode
}

/** الأصل لكل أخطاء الفلوس */
export class MoneyError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'MoneyError'
    // ضرورية لو الـ target في tsconfig قديم — من غيرها instanceof بيفشل
    Object.setPrototypeOf(this, MoneyError.prototype)
  }
}

/** محاولة عملية حسابية بين عملتين مختلفتين */
export class CurrencyMismatchError extends MoneyError {
  constructor(
    readonly left: CurrencyCode,
    readonly right: CurrencyCode,
  ) {
    super(`لا يمكن الجمع بين عملتين مختلفتين: ${left} و ${right}.`)
    this.name = 'CurrencyMismatchError'
    Object.setPrototypeOf(this, CurrencyMismatchError.prototype)
  }
}

/** عملة مش موجودة في السجل */
export class UnknownCurrencyError extends MoneyError {
  constructor(readonly currency: string) {
    super(`عملة غير معروفة: "${currency}".`)
    this.name = 'UnknownCurrencyError'
    Object.setPrototypeOf(this, UnknownCurrencyError.prototype)
  }
}

/**
 * فشل تحويل نص لمبلغ.
 *
 * منفصل عن باقي الأخطاء عن قصد: ده الخطأ الوحيد اللي غالباً سببه
 * مدخل من العميل، فبيتحوّل لـ 400 مش 500.
 */
export class MoneyParseError extends MoneyError {
  constructor(
    readonly input: string,
    reason: string,
  ) {
    super(`مبلغ غير صالح "${input}": ${reason}`)
    this.name = 'MoneyParseError'
    Object.setPrototypeOf(this, MoneyParseError.prototype)
  }
}
