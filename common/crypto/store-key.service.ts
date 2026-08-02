import { Inject, Injectable } from '@nestjs/common'
import * as crypto from 'crypto'
import { KEY_PROVIDER, KeyProvider } from './key-provider.interface'

const ALGORITHM = 'aes-256-gcm'
const IV_LENGTH = 12
const TAG_LENGTH = 16
const DEK_LENGTH = 32

/** إصدار صيغة envelope الخاص بمفاتيح المتاجر */
const ENVELOPE_VERSION = 1

/** نسخة المفتاح المشتق الافتراضية لأي متجر جديد */
export const DEFAULT_DEK_VERSION = 1

/**
 * تخطيط الـ envelope (نسخة 1):
 *
 *   [0]       envelope_version  (1 byte)
 *   [1]       kek_version       (1 byte)
 *   [2]       dek_version       (1 byte)
 *   [3..14]   iv                (12 bytes)
 *   [15..30]  auth_tag          (16 bytes)
 *   [31..]    ciphertext
 *
 * التخطيط ده بيتخزّن في قاعدة البيانات، يعني بيبقى دائم من أول نص
 * مشفّر بيتكتب. أي تعديل عليه لازم يبقى بإصدار جديد، مش تعديل مكانه.
 */
const V1_VERSION_OFFSET = 0
const V1_KEK_VERSION_OFFSET = 1
const V1_DEK_VERSION_OFFSET = 2
const V1_IV_OFFSET = 3
const V1_TAG_OFFSET = V1_IV_OFFSET + IV_LENGTH
const V1_CIPHERTEXT_OFFSET = V1_TAG_OFFSET + TAG_LENGTH
const V1_HEADER_LENGTH = V1_CIPHERTEXT_OFFSET

/** نتيجة التشفير — الـ envelope مع نسخ المفاتيح المستخدمة */
export interface StoreEnvelope {
  /** النص المشفّر في base64 — ده اللي بيتخزّن */
  payload: string
  /** نسخة المفتاح الجذري المستخدمة */
  kekVersion: number
  /** نسخة المفتاح المشتق المستخدمة */
  dekVersion: number
}

/**
 * تشفير بيانات المتاجر بمفتاح مشتق لكل متجر على حدة.
 *
 * الفكرة: بدل ما نخزّن مفتاح منفصل لكل متجر في جدول (وده بيجيب معاه
 * مشكلة توليد وتوزيع وحماية المفاتيح)، بنشتق المفتاح رياضياً من
 * المفتاح الجذري:
 *
 *   DEK = HKDF-SHA256(
 *           ikm  = KEK[kek_version],
 *           salt = "store:<store_id>",
 *           info = "dek:v<dek_version>",
 *           len  = 32
 *         )
 *
 * النتيجة:
 *   • مفيش جدول مفاتيح ومفيش مراسم توليد.
 *   • كل متجر ليه مفتاح مختلف تماماً — تسريب مفتاح متجر مايكشفش غيره.
 *   • تدوير مفتاح متجر واحد = زيادة dek_version بتاعه بس.
 *   • تدوير المفتاح الجذري = زيادة kek_version، والقديم يفضل متاح
 *     للفك لحد ما إعادة التشفير تخلص.
 *
 * نسخ المفاتيح بتتكتب جوه الـ envelope نفسه، فأي نص مشفّر بيحمل معاه
 * المعلومات اللازمة لفكّه.
 */
@Injectable()
export class StoreKeyService {
  constructor(
    @Inject(KEY_PROVIDER) private readonly keyProvider: KeyProvider,
  ) {}

  /**
   * يشتق مفتاح البيانات الخاص بمتجر معيّن.
   *
   * دالة خالصة (deterministic): نفس المدخلات بترجّع نفس المفتاح دايماً.
   * public عشان الاختبارات تقدر تتحقق من خاصية العزل بين المتاجر.
   */
  deriveStoreKey(
    storeId: bigint | number | string,
    dekVersion: number = DEFAULT_DEK_VERSION,
    kekVersion: number = this.keyProvider.currentVersion(),
  ): Buffer {
    if (!Number.isInteger(dekVersion) || dekVersion < 1 || dekVersion > 255) {
      throw new Error(`dek_version لازم يكون رقم صحيح بين 1 و 255 (${dekVersion}).`)
    }

    const normalizedStoreId = this.normalizeStoreId(storeId)
    const kek = this.keyProvider.getKek(kekVersion)

    const salt = Buffer.from(`store:${normalizedStoreId}`, 'utf8')
    const info = Buffer.from(`dek:v${dekVersion}`, 'utf8')

    // crypto.hkdfSync بترجّع ArrayBuffer، فبنلفّها في Buffer
    const derived = crypto.hkdfSync('sha256', kek, salt, info, DEK_LENGTH)

    return Buffer.from(derived)
  }

  /** يشفّر نص عادي لمتجر معيّن */
  encryptForStore(
    storeId: bigint | number | string,
    plainText: string,
    dekVersion: number = DEFAULT_DEK_VERSION,
  ): StoreEnvelope {
    const kekVersion = this.keyProvider.currentVersion()

    if (kekVersion < 1 || kekVersion > 255) {
      throw new Error(`kek_version لازم يكون بين 1 و 255 (${kekVersion}).`)
    }

    const dek = this.deriveStoreKey(storeId, dekVersion, kekVersion)

    const iv = crypto.randomBytes(IV_LENGTH)
    const cipher = crypto.createCipheriv(ALGORITHM, dek, iv)

    const encrypted = Buffer.concat([
      cipher.update(plainText, 'utf8'),
      cipher.final(),
    ])
    const authTag = cipher.getAuthTag()

    const header = Buffer.alloc(3)
    header.writeUInt8(ENVELOPE_VERSION, V1_VERSION_OFFSET)
    header.writeUInt8(kekVersion, V1_KEK_VERSION_OFFSET)
    header.writeUInt8(dekVersion, V1_DEK_VERSION_OFFSET)

    return {
      payload: Buffer.concat([header, iv, authTag, encrypted]).toString(
        'base64',
      ),
      kekVersion,
      dekVersion,
    }
  }

  /**
   * يفك تشفير envelope خاص بمتجر.
   *
   * نسخ المفاتيح بتتقرأ من الـ envelope نفسه، فمش محتاجين نمرّرها.
   * لو الـ storeId غلط، الـ auth tag هيفشل والدالة هترمي خطأ — وده
   * بالظبط خاصية العزل اللي عايزينها.
   */
  decryptForStore(
    storeId: bigint | number | string,
    payload: string,
  ): string {
    const raw = Buffer.from(payload, 'base64')

    if (raw.length <= V1_HEADER_LENGTH) {
      throw new Error('نص مشفّر تالف: الحجم أصغر من الحد الأدنى.')
    }

    const envelopeVersion = raw.readUInt8(V1_VERSION_OFFSET)

    if (envelopeVersion !== ENVELOPE_VERSION) {
      throw new Error(
        `إصدار envelope غير معروف (${envelopeVersion}). ` +
          `الإصدار المدعوم حالياً: ${ENVELOPE_VERSION}.`,
      )
    }

    const kekVersion = raw.readUInt8(V1_KEK_VERSION_OFFSET)
    const dekVersion = raw.readUInt8(V1_DEK_VERSION_OFFSET)

    const dek = this.deriveStoreKey(storeId, dekVersion, kekVersion)

    const iv = raw.subarray(V1_IV_OFFSET, V1_TAG_OFFSET)
    const authTag = raw.subarray(V1_TAG_OFFSET, V1_CIPHERTEXT_OFFSET)
    const encrypted = raw.subarray(V1_CIPHERTEXT_OFFSET)

    const decipher = crypto.createDecipheriv(ALGORITHM, dek, iv)
    decipher.setAuthTag(authTag)

    const decrypted = Buffer.concat([
      decipher.update(encrypted),
      decipher.final(),
    ])

    return decrypted.toString('utf8')
  }

  /** helper: يشفّر object كامل لمتجر */
  encryptJsonForStore(
    storeId: bigint | number | string,
    obj: Record<string, any>,
    dekVersion: number = DEFAULT_DEK_VERSION,
  ): StoreEnvelope {
    return this.encryptForStore(storeId, JSON.stringify(obj), dekVersion)
  }

  /** helper: يفك ويرجّع object، أو null لو مفيش بيانات أو فشل الفك */
  decryptJsonForStore<T = Record<string, any>>(
    storeId: bigint | number | string,
    payload: string | null | undefined,
  ): T | null {
    if (!payload) return null

    try {
      return JSON.parse(this.decryptForStore(storeId, payload)) as T
    } catch {
      return null
    }
  }

  /**
   * يقرأ نسخ المفاتيح من envelope من غير ما يفك التشفير.
   * مفيدة في التقارير وفي تحديد أي الصفوف محتاجة إعادة تشفير بعد التدوير.
   */
  readEnvelopeVersions(
    payload: string,
  ): { envelopeVersion: number; kekVersion: number; dekVersion: number } {
    const raw = Buffer.from(payload, 'base64')

    if (raw.length <= V1_HEADER_LENGTH) {
      throw new Error('نص مشفّر تالف: الحجم أصغر من الحد الأدنى.')
    }

    return {
      envelopeVersion: raw.readUInt8(V1_VERSION_OFFSET),
      kekVersion: raw.readUInt8(V1_KEK_VERSION_OFFSET),
      dekVersion: raw.readUInt8(V1_DEK_VERSION_OFFSET),
    }
  }

  /** توحيد شكل معرّف المتجر — BigInt و number و string لازم يدّوا نفس المفتاح */
  private normalizeStoreId(storeId: bigint | number | string): string {
    const value = String(storeId).trim()

    if (value.length === 0) {
      throw new Error('store_id مطلوب لاشتقاق مفتاح المتجر.')
    }

    return value
  }
}
