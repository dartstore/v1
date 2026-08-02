import { Inject, Injectable } from '@nestjs/common'
import * as crypto from 'crypto'
import {
  assertKeyVersion,
  buildAad,
  CIPHER_ALGORITHM,
  DERIVED_KEY_LENGTH,
  DecryptionError,
  ENVELOPE_HEADER_LENGTH,
  ENVELOPE_VERSION,
  EncryptionContext,
  EnvelopeScope,
  IV_LENGTH,
  KEY_PROVIDER,
  KeyProvider,
  OFFSET_CIPHERTEXT,
  OFFSET_DERIVED_KEY_VERSION,
  OFFSET_ENVELOPE_VERSION,
  OFFSET_IV,
  OFFSET_KEK_VERSION,
  OFFSET_SCOPE,
  OFFSET_TAG,
  packEnvelopeHeader,
  wipe,
} from './key-provider.interface'

/** نسخة المفتاح المشتق الافتراضية لأي متجر جديد */
export const DEFAULT_DEK_VERSION = 1

/** ناتج التشفير — النص المخزّن مع نسخ المفاتيح المستخدمة */
export interface StoreEnvelope {
  /** النص المشفّر في base64 — ده اللي بيتخزّن في العمود */
  payload: string
  /** نسخة المفتاح الجذري المستخدمة */
  kekVersion: number
  /** نسخة المفتاح المشتق المستخدمة */
  dekVersion: number
}

/**
 * تشفير بيانات المتاجر بمفتاح مشتق لكل متجر على حدة.
 *
 * الاشتقاق:
 *
 *   DEK = HKDF-SHA256(
 *           ikm  = KEK[kek_version],
 *           salt = "store:<store_id>",
 *           info = "dek:v<dek_version>:kek:v<kek_version>",
 *           len  = 32)
 *
 * ليه اشتقاق بدل جدول مفاتيح:
 *   • مفيش جدول، ولا مراسم توليد، ولا مشكلة توزيع.
 *   • كل متجر ليه مفتاح مختلف تماماً.
 *   • تدوير مفتاح متجر واحد = زيادة dek_version بتاعه بس.
 *   • تدوير المفتاح الجذري = زيادة kek_version، والقديم يفضل متاح
 *     للفك لحد ما إعادة التشفير تخلص.
 *
 * طبقتين عزل مختلفتين — الاتنين لازمين:
 *
 *   1. **بين المتاجر** — عن طريق مفتاح مشتق مختلف. متجر مايقدرش
 *      يفك تشفير بيانات متجر تاني، حتى لو نقلنا الصف بنفسنا.
 *
 *   2. **جوه المتجر الواحد** — عن طريق الـ AAD. كل الصفوف بتاعة نفس
 *      المتجر بتستخدم نفس الـ DEK، فمن غير AAD كان ينفع تنقل النص
 *      المشفّر من صف test لصف live، أو من بوابة لبوابة، وهيتفك عادي.
 *      الـ AAD بيربط النص بـ (المتجر، الوضع، نوع الصف، معرّف الصف،
 *      اسم الحقل) وبيخلي النقل ده يفشل.
 *
 * ملاحظة على الأداء: المفتاح بيتشتق مع كل عملية ومابيتخزّنش في كاش.
 * HKDF-SHA256 عمليتين HMAC بس (ميكروثانية)، والمقابل إننا مابنحتفظش
 * بمفاتيح مستأجرين في الذاكرة لفترات طويلة. المقايضة دي مقصودة.
 *
 * حدود الاستخدام: نفس حد الـ IV العشوائي (~2^32 عملية لكل مفتاح).
 * مناسب للاعتمادات، مش للبيانات عالية الحجم.
 */
@Injectable()
export class StoreKeyService {
  constructor(
    @Inject(KEY_PROVIDER) private readonly keyProvider: KeyProvider,
  ) {}

  /**
   * يشتق مفتاح البيانات الخاص بمتجر.
   *
   * دالة حتمية: نفس المدخلات بترجّع نفس المفتاح دايماً.
   * public عشان الاختبارات تقدر تتحقق من خاصية العزل مباشرةً.
   *
   * المسؤولية على المستدعي إنه يمسح الناتج (wipe) بعد الاستخدام.
   */
  async deriveStoreKey(
    storeId: bigint | number | string,
    dekVersion: number = DEFAULT_DEK_VERSION,
    kekVersion?: number,
  ): Promise<Buffer> {
    assertKeyVersion('dek_version', dekVersion)

    const resolvedKekVersion =
      kekVersion ?? (await this.keyProvider.currentKekVersion())

    assertKeyVersion('kek_version', resolvedKekVersion)

    const normalizedStoreId = this.normalizeStoreId(storeId)
    const kek = await this.keyProvider.getKek(resolvedKekVersion)

    try {
      const derived = crypto.hkdfSync(
        'sha256',
        kek,
        Buffer.from(`store:${normalizedStoreId}`, 'utf8'),
        Buffer.from(`dek:v${dekVersion}:kek:v${resolvedKekVersion}`, 'utf8'),
        DERIVED_KEY_LENGTH,
      )

      return Buffer.from(derived)
    } finally {
      wipe(kek)
    }
  }

  /**
   * يشفّر نص عادي لمتجر معيّن.
   *
   * @param storeId    معرّف المتجر
   * @param plainText  النص
   * @param context    سياق ثابت بيتربط بيه النص
   * @param dekVersion نسخة مفتاح المتجر (بتزيد عند تدوير مفتاح المتجر)
   */
  async encryptForStore(
    storeId: bigint | number | string,
    plainText: string,
    context: EncryptionContext,
    dekVersion: number = DEFAULT_DEK_VERSION,
  ): Promise<StoreEnvelope> {
    assertKeyVersion('dek_version', dekVersion)

    const kekVersion = await this.keyProvider.currentKekVersion()
    assertKeyVersion('kek_version', kekVersion)

    const normalizedStoreId = this.normalizeStoreId(storeId)
    const dek = await this.deriveStoreKey(
      normalizedStoreId,
      dekVersion,
      kekVersion,
    )

    try {
      const iv = crypto.randomBytes(IV_LENGTH)
      const aad = buildAad(EnvelopeScope.Store, normalizedStoreId, context)

      const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, dek, iv)
      cipher.setAAD(aad)

      const encrypted = Buffer.concat([
        cipher.update(plainText, 'utf8'),
        cipher.final(),
      ])
      const authTag = cipher.getAuthTag()

      const header = packEnvelopeHeader({
        envelopeVersion: ENVELOPE_VERSION,
        scope: EnvelopeScope.Store,
        kekVersion,
        derivedKeyVersion: dekVersion,
      })

      return {
        payload: Buffer.concat([header, iv, authTag, encrypted]).toString(
          'base64',
        ),
        kekVersion,
        dekVersion,
      }
    } finally {
      wipe(dek)
    }
  }

  /**
   * يفك تشفير envelope خاص بمتجر.
   *
   * نسخ المفاتيح بتتقرأ من الـ envelope نفسه. السياق لازم يبقى نفسه
   * اللي اتشفّر بيه بالظبط.
   *
   * @throws {DecryptionError} بـ reason='integrity' لو المتجر غلط، أو
   *         السياق مختلف، أو في عبث بالبيانات
   */
  async decryptForStore(
    storeId: bigint | number | string,
    payload: string,
    context: EncryptionContext,
  ): Promise<string> {
    const raw = Buffer.from(payload, 'base64')

    if (raw.length <= ENVELOPE_HEADER_LENGTH) {
      throw new DecryptionError(
        'malformed',
        'نص مشفّر تالف: الحجم أصغر من الحد الأدنى.',
      )
    }

    const envelopeVersion = raw.readUInt8(OFFSET_ENVELOPE_VERSION)

    if (envelopeVersion !== ENVELOPE_VERSION) {
      throw new DecryptionError(
        'unsupported_version',
        `إصدار envelope غير معروف (${envelopeVersion}). ` +
          `الإصدار المدعوم: ${ENVELOPE_VERSION}.`,
      )
    }

    const scope = raw.readUInt8(OFFSET_SCOPE)

    if (scope !== EnvelopeScope.Store) {
      throw new DecryptionError(
        'malformed',
        `النص ده نطاقه ${scope} مش نطاق متجر. ` +
          `لو نطاقه المنصة استخدم EncryptionService.`,
      )
    }

    const kekVersion = raw.readUInt16BE(OFFSET_KEK_VERSION)
    const dekVersion = raw.readUInt16BE(OFFSET_DERIVED_KEY_VERSION)

    const normalizedStoreId = this.normalizeStoreId(storeId)

    let dek: Buffer

    try {
      dek = await this.deriveStoreKey(
        normalizedStoreId,
        dekVersion,
        kekVersion,
      )
    } catch (error) {
      throw new DecryptionError('key_unavailable', (error as Error).message)
    }

    try {
      const iv = raw.subarray(OFFSET_IV, OFFSET_TAG)
      const authTag = raw.subarray(OFFSET_TAG, OFFSET_CIPHERTEXT)
      const encrypted = raw.subarray(OFFSET_CIPHERTEXT)
      const aad = buildAad(EnvelopeScope.Store, normalizedStoreId, context)

      const decipher = crypto.createDecipheriv(CIPHER_ALGORITHM, dek, iv)
      decipher.setAAD(aad)
      decipher.setAuthTag(authTag)

      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final(),
      ])

      return decrypted.toString('utf8')
    } catch (error) {
      if (error instanceof DecryptionError) throw error

      throw new DecryptionError(
        'integrity',
        'فشل التحقق من سلامة النص المشفّر. ' +
          'الاحتمالات: متجر غلط، أو سياق مختلف (وضع/صف/حقل)، ' +
          'أو عبث بالبيانات. الحالة دي تستدعي تنبيه أمني.',
      )
    } finally {
      wipe(dek)
    }
  }

  /** helper: يشفّر object كامل لمتجر */
  async encryptJsonForStore(
    storeId: bigint | number | string,
    obj: Record<string, any>,
    context: EncryptionContext,
    dekVersion: number = DEFAULT_DEK_VERSION,
  ): Promise<StoreEnvelope> {
    return this.encryptForStore(
      storeId,
      JSON.stringify(obj),
      context,
      dekVersion,
    )
  }

  /**
   * helper: يفك ويرجّع object.
   *
   * ⚠️ بيرجّع null بس لو المدخل فاضي. أخطاء السلامة بترمي
   * DecryptionError عشان العبث مايتخفيش ورا قيمة فاضية.
   */
  async decryptJsonForStore<T = Record<string, any>>(
    storeId: bigint | number | string,
    payload: string | null | undefined,
    context: EncryptionContext,
  ): Promise<T | null> {
    if (!payload) return null

    return JSON.parse(
      await this.decryptForStore(storeId, payload, context),
    ) as T
  }

  /**
   * يقرأ بيانات الهيدر من غير فك تشفير.
   * مفيدة في تحديد الصفوف المحتاجة إعادة تشفير بعد تدوير المفاتيح.
   */
  readEnvelopeHeader(payload: string): {
    envelopeVersion: number
    scope: number
    kekVersion: number
    dekVersion: number
  } {
    const raw = Buffer.from(payload, 'base64')

    if (raw.length <= ENVELOPE_HEADER_LENGTH) {
      throw new DecryptionError(
        'malformed',
        'نص مشفّر تالف: الحجم أصغر من الحد الأدنى.',
      )
    }

    return {
      envelopeVersion: raw.readUInt8(OFFSET_ENVELOPE_VERSION),
      scope: raw.readUInt8(OFFSET_SCOPE),
      kekVersion: raw.readUInt16BE(OFFSET_KEK_VERSION),
      dekVersion: raw.readUInt16BE(OFFSET_DERIVED_KEY_VERSION),
    }
  }

  /**
   * توحيد معرّف المتجر **عددياً**.
   *
   * BigInt و number و string لازم يدّوا نفس المفتاح، و "042" لازم
   * تدّي نفس مفتاح 42. التوحيد النصي البسيط (trim) كان هيخلي الشكلين
   * دول مفتاحين مختلفين، ونص مشفّر يبقى مستحيل فكّه لو الاستدعاء
   * التاني جه بشكل مختلف.
   */
  private normalizeStoreId(storeId: bigint | number | string): string {
    if (typeof storeId === 'bigint') {
      return this.assertNonNegative(storeId)
    }

    if (typeof storeId === 'number') {
      if (!Number.isSafeInteger(storeId)) {
        throw new Error(
          `store_id لازم يكون عدد صحيح آمن (استلمنا: ${storeId}).`,
        )
      }
      return this.assertNonNegative(BigInt(storeId))
    }

    const trimmed = String(storeId).trim()

    if (!/^\d+$/.test(trimmed)) {
      throw new Error(
        `store_id لازم يكون رقم صحيح موجب (استلمنا: "${storeId}").`,
      )
    }

    return this.assertNonNegative(BigInt(trimmed))
  }

  private assertNonNegative(value: bigint): string {
    if (value < 0n) {
      throw new Error(`store_id ماينفعش يكون سالب (استلمنا: ${value}).`)
    }

    return value.toString()
  }
}
