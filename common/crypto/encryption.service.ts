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

/** نسخة مفتاح المنصة المشتق — بتزيد لو غيّرنا طريقة الاشتقاق */
export const PLATFORM_KEY_VERSION = 1

/**
 * تشفير البيانات الحساسة على مستوى المنصة (مش مرتبطة بمتجر).
 *
 * لبيانات المتاجر — زي بيانات اعتماد بوابات الدفع — استخدم
 * StoreKeyService بدل دي. هي اللي بتضمن العزل بين المستأجرين.
 *
 * ثلاث ضمانات أساسية:
 *
 *  1. المفتاح الجذري (KEK) **مابيتستخدمش كمفتاح تشفير مباشرةً**.
 *     بيتشتق منه مفتاح منصة مخصّص بـ HKDF. كده الـ KEK دوره الوحيد
 *     في المشروع كله إنه مادة اشتقاق، ومفيش خلط بين الأدوار.
 *
 *  2. كل نص مشفّر مربوط بمكانه المنطقي عن طريق AAD. النص المنقول من
 *     صف لصف تاني، أو من وضع test لوضع live، بيفشل التحقق.
 *
 *  3. فشل التحقق من السلامة بيترمي كخطأ صريح، مش بيترجع كـ null.
 *     العبث لازم يتعامل معاه كحادث أمني.
 *
 * حدود الاستخدام: الـ IV عشوائي 96-bit، وده بيحدّ الاستخدام الآمن
 * لنفس المفتاح بحوالي 2^32 عملية تشفير. مناسب تماماً لبيانات بتتكتب
 * نادراً زي الاعتمادات. ❌ ماتستخدمش الخدمة دي لبيانات عالية الحجم
 * زي حمولات الـ webhooks.
 */
@Injectable()
export class EncryptionService {
  constructor(
    @Inject(KEY_PROVIDER) private readonly keyProvider: KeyProvider,
  ) {}

  /**
   * يشفّر نص عادي في نطاق المنصة.
   *
   * @param plainText النص المطلوب تشفيره
   * @param context   سياق ثابت بيتربط بيه النص (mode/recordType/recordId/field)
   */
  async encrypt(
    plainText: string,
    context: EncryptionContext,
  ): Promise<string> {
    // بناء الـ AAD الأول: أي خطأ هنا خطأ برمجي، ولازم يطلع زي ما هو
    // من غير ما يتحوّل لخطأ تشفير.
    const aad = buildAad(EnvelopeScope.Platform, null, context)

    const kekVersion = await this.keyProvider.currentKekVersion()
    assertKeyVersion('kek_version', kekVersion)

    const platformKey = await this.derivePlatformKey(
      kekVersion,
      PLATFORM_KEY_VERSION,
    )

    try {
      const iv = crypto.randomBytes(IV_LENGTH)

      const cipher = crypto.createCipheriv(CIPHER_ALGORITHM, platformKey, iv)
      cipher.setAAD(aad)

      const encrypted = Buffer.concat([
        cipher.update(plainText, 'utf8'),
        cipher.final(),
      ])
      const authTag = cipher.getAuthTag()

      const header = packEnvelopeHeader({
        envelopeVersion: ENVELOPE_VERSION,
        scope: EnvelopeScope.Platform,
        kekVersion,
        derivedKeyVersion: PLATFORM_KEY_VERSION,
      })

      return Buffer.concat([header, iv, authTag, encrypted]).toString('base64')
    } finally {
      wipe(platformKey)
    }
  }

  /**
   * يفك تشفير envelope في نطاق المنصة.
   *
   * لازم يتبعت نفس السياق اللي اتشفّر بيه بالظبط، وإلا هيفشل التحقق.
   *
   * @throws {DecryptionError} بـ reason='integrity' لو في عبث أو نقل
   */
  async decrypt(payload: string, context: EncryptionContext): Promise<string> {
    const raw = Buffer.from(payload, 'base64')

    // "أصغر من" مش "أصغر من أو يساوي": في GCM طول النص المشفّر بيساوي
    // طول النص الأصلي، فتشفير نص فاضي بيدّي envelope طوله الهيدر بالظبط
    // وهو envelope صالح تماماً.
    if (raw.length < ENVELOPE_HEADER_LENGTH) {
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

    if (scope !== EnvelopeScope.Platform) {
      throw new DecryptionError(
        'malformed',
        `النص ده نطاقه ${scope} مش نطاق المنصة. ` +
          `لو نطاقه متجر استخدم StoreKeyService.`,
      )
    }

    // بناء الـ AAD خارج الـ try عن قصد: أخطاء التحقق من السياق أخطاء
    // برمجية، وماينفعش تتحوّل لـ reason='integrity' وتولّد تنبيه أمني كاذب.
    const aad = buildAad(EnvelopeScope.Platform, null, context)

    const kekVersion = raw.readUInt16BE(OFFSET_KEK_VERSION)
    const derivedKeyVersion = raw.readUInt16BE(OFFSET_DERIVED_KEY_VERSION)

    const platformKey = await this.derivePlatformKeyOrThrow(
      kekVersion,
      derivedKeyVersion,
    )

    try {
      const iv = raw.subarray(OFFSET_IV, OFFSET_TAG)
      const authTag = raw.subarray(OFFSET_TAG, OFFSET_CIPHERTEXT)
      const encrypted = raw.subarray(OFFSET_CIPHERTEXT)

      const decipher = crypto.createDecipheriv(
        CIPHER_ALGORITHM,
        platformKey,
        iv,
      )
      decipher.setAAD(aad)
      decipher.setAuthTag(authTag)

      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final(),
      ])

      return decrypted.toString('utf8')
    } catch {
      // الكتلة دي بقت محصورة في عمليات التشفير نفسها بس، فأي فشل هنا
      // هو فعلاً فشل تحقق من السلامة.
      throw new DecryptionError(
        'integrity',
        'فشل التحقق من سلامة النص المشفّر. ' +
          'الاحتمالات: عبث بالبيانات، أو نقل النص لصف/وضع تاني، أو مفتاح غلط. ' +
          'الحالة دي تستدعي تنبيه أمني.',
      )
    } finally {
      wipe(platformKey)
    }
  }

  /** helper: يشفّر object كامل */
  async encryptJson(
    obj: Record<string, any>,
    context: EncryptionContext,
  ): Promise<string> {
    return this.encrypt(JSON.stringify(obj), context)
  }

  /**
   * helper: يفك ويرجّع object.
   *
   * ⚠️ بيرجّع null **بس** لو المدخل فاضي (يعني الحقل مش متظبط أصلاً).
   * أخطاء السلامة بترمي DecryptionError. النسخة القديمة كانت بتبلع كل
   * الأخطاء وترجّع null، وده كان بيخفي العبث ويخليه شكله زي
   * "مفيش بيانات".
   */
  async decryptJson<T = Record<string, any>>(
    payload: string | null | undefined,
    context: EncryptionContext,
  ): Promise<T | null> {
    if (!payload) return null

    return JSON.parse(await this.decrypt(payload, context)) as T
  }

  /**
   * نفس derivePlatformKey لكن بيحوّل فشل جلب المفتاح لـ DecryptionError.
   *
   * منفصلة عشان المستدعي يقدر يستخدم const بدل let، ومايبقاش في أي
   * التباس عند TypeScript حوالين "استُخدم قبل الإسناد".
   */
  private async derivePlatformKeyOrThrow(
    kekVersion: number,
    platformKeyVersion: number,
  ): Promise<Buffer> {
    try {
      return await this.derivePlatformKey(kekVersion, platformKeyVersion)
    } catch (error) {
      throw new DecryptionError('key_unavailable', (error as Error).message)
    }
  }

  /**
   * يشتق مفتاح المنصة من المفتاح الجذري.
   *
   *   platformKey = HKDF-SHA256(
   *                   ikm  = KEK[kek_version],
   *                   salt = "platform",
   *                   info = "platform:v<n>",
   *                   len  = 32)
   */
  private async derivePlatformKey(
    kekVersion: number,
    platformKeyVersion: number,
  ): Promise<Buffer> {
    assertKeyVersion('platform_key_version', platformKeyVersion)

    const kek = await this.keyProvider.getKek(kekVersion)

    try {
      const derived = crypto.hkdfSync(
        'sha256',
        kek,
        Buffer.from('platform', 'utf8'),
        Buffer.from(`platform:v${platformKeyVersion}`, 'utf8'),
        DERIVED_KEY_LENGTH,
      )

      return Buffer.from(derived)
    } finally {
      wipe(kek)
    }
  }
}
