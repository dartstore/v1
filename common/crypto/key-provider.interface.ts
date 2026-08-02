import * as crypto from 'crypto'

/**
 * ══════════════════════════════════════════════════════════════════
 * عقود التشفير المشتركة
 * ══════════════════════════════════════════════════════════════════
 *
 * الملف ده فيه ثلاث حاجات:
 *   1. عقد مزوّد المفاتيح الجذرية (KeyProvider)
 *   2. صيغة الـ envelope الدائمة
 *   3. بناء الـ AAD (البيانات المصادَق عليها)
 *
 * ليه كلهم في ملف واحد: ده الملف الوحيد في مجلد crypto اللي مالوش أي
 * اعتماد على ملف تاني، فهو جذر شجرة الاعتماديات ومفيش احتمال دورة
 * اعتماد. لو الجزء بتاع الـ envelope كبر، ينفصل في ملف مستقل وقتها.
 *
 * ⚠️ صيغة الـ envelope والـ AAD بيبقوا دائمين من أول نص مشفّر بيتخزّن
 * في الداتابيز. أي تعديل عليهم لازم يبقى بإصدار جديد (ENVELOPE_VERSION)
 * مش تعديل في مكانه.
 */

/* ═══════════════════════════════════════════════════════════════════
   1. عقد مزوّد المفاتيح
   ═══════════════════════════════════════════════════════════════════ */

/**
 * مصدر المفاتيح الجذرية (KEK).
 *
 * العقد كله async عن قصد. كل أنظمة إدارة المفاتيح الحقيقية
 * (AWS KMS / GCP KMS / Vault / HSM) واجهاتها غير متزامنة، فلو العقد
 * كان sync كان هيبقى مستحيل نستبدل المزوّد من غير ما نغيّر توقيع كل
 * دالة تشفير في المشروع.
 *
 * حدود معروفة ومقصودة: اشتقاق المفاتيح بـ HKDF بيتطلب وجود المفتاح
 * الجذري في ذاكرة التطبيق. يعني ده متوافق مع KMS اللي بيحفظ ويسلّم
 * المفتاح وقت الإقلاع (Secrets Manager، أو KMS Decrypt لمفتاح ملفوف)،
 * بس مش متوافق مع HSM اللي المفتاح مابيخرجش منه أبداً. الوضع التاني
 * محتاج DEK ملفوف مخزّن مع كل صف — وده ينفّذ كـ ENVELOPE_VERSION = 2
 * من غير ما نلمس البيانات القديمة.
 */
export interface KeyProvider {
  /** رقم نسخة المفتاح المستخدم في أي تشفير جديد */
  currentKekVersion(): Promise<number>

  /**
   * يرجّع المفتاح الجذري لنسخة معيّنة (32 byte).
   * لازم يرجّع نسخة منفصلة (defensive copy) مش مرجع للمخزّن الداخلي.
   * يرمي خطأ لو النسخة دي مش متاحة.
   */
  getKek(version: number): Promise<Buffer>

  /** كل النسخ المتاحة حالياً — للتشخيص وتقارير إعادة التشفير */
  availableVersions(): Promise<number[]>

  /**
   * قيمة تحقق من المفتاح (Key Check Value).
   * أول 4 بايت من HMAC-SHA256(kek, "kcv:v1") بصيغة hex.
   * بتتسجّل وقت الإقلاع عشان مفتاح غلط يتكشف من أول لحظة، مش عند
   * أول عملية دفع لعميل حقيقي.
   */
  keyCheckValue(version: number): Promise<string>
}

/** توكن الحقن — الواجهات في TypeScript مش موجودة وقت التشغيل */
export const KEY_PROVIDER = Symbol('KEY_PROVIDER')

/** الطول المطلوب للمفتاح الجذري */
export const KEK_LENGTH_BYTES = 32

/** أقصى رقم نسخة يقدر الـ envelope يحمله (حقل 2 byte) */
export const MAX_KEY_VERSION = 65535

/** يحسب الـ KCV لمفتاح — دالة خالصة، مشتركة بين المزوّدين */
export function computeKeyCheckValue(kek: Buffer): string {
  return crypto
    .createHmac('sha256', kek)
    .update('kcv:v1', 'utf8')
    .digest()
    .subarray(0, 4)
    .toString('hex')
}

/* ═══════════════════════════════════════════════════════════════════
   2. صيغة الـ envelope
   ═══════════════════════════════════════════════════════════════════ */

/**
 * التخطيط (الإصدار 1):
 *
 *   [0]        envelope_version     1 byte
 *   [1]        scope                1 byte   (1 = منصة، 2 = متجر)
 *   [2..3]     kek_version          2 bytes  big-endian
 *   [4..5]     derived_key_version  2 bytes  big-endian
 *   [6..17]    iv                   12 bytes
 *   [18..33]   auth_tag             16 bytes
 *   [34..]     ciphertext           الباقي (ممكن يكون صفر بايت)
 *
 * كله متجمّع في base64 واحد.
 *
 * حقول النسخ 2 byte مش 1: تدوير المفاتيح على مدى سنين، ولكل متجر على
 * حدة، ممكن يعدّي 255 تدوير. الحد بـ byte واحد كان هيظهر كخطأ وقت
 * التشغيل على مسار كتابة دفع حقيقي.
 *
 * ⚠️ ملحوظة مهمة على الطول: في وضع GCM طول النص المشفّر بيساوي طول
 * النص الأصلي بالظبط. يعني تشفير نص فاضي بيدّي envelope طوله
 * ENVELOPE_HEADER_LENGTH بالضبط. أي فحص طول لازم يستخدم "أصغر من"
 * مش "أصغر من أو يساوي".
 *
 * الـ AAD مش متخزّن جوه الـ envelope — بيتبني من جديد وقت الفك من
 * أعمدة الصف نفسه. ده المقصود: لو النص المشفّر اتنقل لصف تاني، الـ AAD
 * المعاد بناؤه هيبقى مختلف والـ auth tag هيفشل.
 */
export const ENVELOPE_VERSION = 1

export enum EnvelopeScope {
  /** مفتاح مشتق على مستوى المنصة — مش مرتبط بمتجر */
  Platform = 1,
  /** مفتاح مشتق لمتجر بعينه */
  Store = 2,
}

export const IV_LENGTH = 12
export const TAG_LENGTH = 16
export const DERIVED_KEY_LENGTH = 32
export const CIPHER_ALGORITHM = 'aes-256-gcm'

export const OFFSET_ENVELOPE_VERSION = 0
export const OFFSET_SCOPE = 1
export const OFFSET_KEK_VERSION = 2
export const OFFSET_DERIVED_KEY_VERSION = 4

/**
 * طول البادئة الوصفية (الإصدار + النطاق + نسختين المفاتيح).
 * ثابت صريح بدل حساب ضمني، عشان أي تعديل مستقبلي على التخطيط يبان
 * في مكان واحد.
 */
export const ENVELOPE_PREFIX_LENGTH = 6

export const OFFSET_IV = ENVELOPE_PREFIX_LENGTH
export const OFFSET_TAG = OFFSET_IV + IV_LENGTH
export const OFFSET_CIPHERTEXT = OFFSET_TAG + TAG_LENGTH
export const ENVELOPE_HEADER_LENGTH = OFFSET_CIPHERTEXT

export interface EnvelopeHeader {
  envelopeVersion: number
  scope: EnvelopeScope
  kekVersion: number
  derivedKeyVersion: number
}

/** يبني بادئة الـ envelope (6 bytes) */
export function packEnvelopeHeader(header: EnvelopeHeader): Buffer {
  const buffer = Buffer.alloc(ENVELOPE_PREFIX_LENGTH)

  buffer.writeUInt8(header.envelopeVersion, OFFSET_ENVELOPE_VERSION)
  buffer.writeUInt8(header.scope, OFFSET_SCOPE)
  buffer.writeUInt16BE(header.kekVersion, OFFSET_KEK_VERSION)
  buffer.writeUInt16BE(header.derivedKeyVersion, OFFSET_DERIVED_KEY_VERSION)

  return buffer
}

/* ═══════════════════════════════════════════════════════════════════
   3. أخطاء فك التشفير
   ═══════════════════════════════════════════════════════════════════ */

export type DecryptionFailureReason =
  /** الحجم أصغر من الحد الأدنى، أو النطاق مش المتوقع */
  | 'malformed'
  /** إصدار envelope مش مدعوم في النسخة الحالية من الكود */
  | 'unsupported_version'
  /** المفتاح المطلوب مش متاح في البيئة الحالية */
  | 'key_unavailable'
  /**
   * فشل التحقق من الـ auth tag.
   *
   * ⚠️ ده مش خطأ عادي. معناه واحد من تلاتة:
   *   • النص المشفّر اتعدّل (عبث)
   *   • النص اتنقل من صف لصف تاني (AAD مختلف)
   *   • المفتاح غلط
   * كل الحالات دي لازم تولّد تنبيه أمني، مش تتبلع بصمت.
   */
  | 'integrity'

export class DecryptionError extends Error {
  /**
   * هل ده انتهاك سلامة يستدعي تنبيه أمني؟
   *
   * حقل عادي مش getter: الـ getters بتتعرّف على الـ prototype، ومطابقات
   * الاختبارات (toMatchObject) بتقارن الخصائص المملوكة للكائن نفسه.
   */
  readonly isSecurityRelevant: boolean

  constructor(
    readonly reason: DecryptionFailureReason,
    message: string,
  ) {
    super(message)

    this.name = 'DecryptionError'
    this.isSecurityRelevant = reason === 'integrity'

    // ضرورية لو الـ target في tsconfig قديم (ES5/ES2015): من غيرها
    // instanceof بيفشل على الأصناف اللي بترث من Error.
    Object.setPrototypeOf(this, DecryptionError.prototype)
  }
}

/* ═══════════════════════════════════════════════════════════════════
   4. سياق التشفير و AAD
   ═══════════════════════════════════════════════════════════════════ */

/**
 * وضع التشغيل.
 *
 * نوع TypeScript محلي، مش enum في Prisma — المرحلة صفر مافيهاش أي
 * تغيير على الداتابيز. الـ enum اللي هييجي في المرحلة الأولى هيبقى
 * متوافق معاه شكلاً.
 */
export type CryptoMode = 'test' | 'live'

/**
 * السياق اللي بيتربط بيه النص المشفّر.
 *
 * ⚠️ كل قيمة هنا لازم تكون **ثابتة مدى حياة الصف**. لو حقل متغيّر
 * دخل في الـ AAD، أول تعديل عليه هيخلي النص المشفّر مستحيل فكّه.
 * يعني: ماينفعش اسم عرض، ولا slug، ولا أي حقل المستخدم بيعدّله.
 *
 * ملاحظة عملية للمرحلة الأولى: recordId لازم يكون معروف قبل التشفير.
 * الصف اللي بيتعمل وبيتشفّر في نفس اللحظة محتاج إما إن الـ id يتحجز
 * الأول، أو إن التشفير يحصل في update بعد الإدراج. القرار ده بيتاخد
 * مع أول كيان دفع، مش هنا.
 */
export interface EncryptionContext {
  mode: CryptoMode
  /** نوع الكيان، مثال: 'payment_account' */
  recordType: string
  /** المعرّف الثابت للصف */
  recordId: string
  /** اسم العمود، مثال: 'credentials' */
  field: string
}

const AAD_MAGIC = 'aad:v1'

/** يشفّر عنصر واحد بطول مسبوق — عشان يبقى الترميز غير قابل للالتباس */
function writeLengthPrefixed(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8')

  if (bytes.length > 0xffff) {
    throw new Error(`عنصر AAD أطول من المسموح (${bytes.length} byte).`)
  }

  const length = Buffer.alloc(2)
  length.writeUInt16BE(bytes.length, 0)

  return Buffer.concat([length, bytes])
}

/**
 * يبني الـ AAD بترميز غير قابل للالتباس.
 *
 * كل عنصر مسبوق بطوله (2 byte)، فمفيش احتمال إن مجموعة عناصر تدّي نفس
 * الناتج بتاع مجموعة تانية. لو استخدمنا فاصل نصي عادي كان ممكن قيمة
 * فيها الفاصل تعمل التباس.
 *
 * ⚠️ الدالة دي بترمي Error عادي (مش DecryptionError) لو السياق ناقص،
 * لأن ده خطأ برمجي مش حادث أمني. المستدعي لازم يستدعيها **قبل** أي
 * كتلة try بتحوّل الأخطاء لـ integrity.
 *
 * @param scope    نطاق المفتاح (منصة / متجر)
 * @param storeId  معرّف المتجر الموحّد، أو null لنطاق المنصة
 * @param context  سياق الصف
 */
export function buildAad(
  scope: EnvelopeScope,
  storeId: string | null,
  context: EncryptionContext,
): Buffer {
  validateContext(context)

  return Buffer.concat([
    writeLengthPrefixed(AAD_MAGIC),
    writeLengthPrefixed(String(scope)),
    writeLengthPrefixed(storeId ?? ''),
    writeLengthPrefixed(context.mode),
    writeLengthPrefixed(context.recordType),
    writeLengthPrefixed(context.recordId),
    writeLengthPrefixed(context.field),
  ])
}

function validateContext(context: EncryptionContext): void {
  if (!context) {
    throw new Error('سياق التشفير مطلوب.')
  }

  if (context.mode !== 'test' && context.mode !== 'live') {
    throw new Error(
      `mode لازم يكون 'test' أو 'live' (استلمنا: ${String(context.mode)}).`,
    )
  }

  const required: Array<[string, string]> = [
    ['recordType', context.recordType],
    ['recordId', context.recordId],
    ['field', context.field],
  ]

  for (const [name, value] of required) {
    if (typeof value !== 'string' || value.trim().length === 0) {
      throw new Error(`${name} مطلوب في سياق التشفير ومش ممكن يكون فاضي.`)
    }
  }
}

/* ═══════════════════════════════════════════════════════════════════
   5. أدوات مشتركة
   ═══════════════════════════════════════════════════════════════════ */

/** يمسح مفتاح من الذاكرة بعد الاستخدام */
export function wipe(buffer: Buffer): void {
  buffer.fill(0)
}

/** يتحقق إن رقم النسخة يسع في حقل 2 byte */
export function assertKeyVersion(name: string, version: number): void {
  if (!Number.isInteger(version) || version < 1 || version > MAX_KEY_VERSION) {
    throw new Error(
      `${name} لازم يكون رقم صحيح بين 1 و ${MAX_KEY_VERSION} (استلمنا: ${version}).`,
    )
  }
}
