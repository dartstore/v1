import { EncryptionService } from './encryption.service'
import { KeyProvider } from './key-provider.interface'

/** مزوّد مفاتيح ثابت للاختبارات — مفتاحين لاختبار التدوير */
class StubKeyProvider implements KeyProvider {
  constructor(
    private readonly keys: Map<number, Buffer>,
    private readonly current: number,
  ) {}

  currentVersion(): number {
    return this.current
  }

  getKek(version: number): Buffer {
    const key = this.keys.get(version)
    if (!key) throw new Error(`مفتاح نسخة ${version} مش متاح`)
    return key
  }
}

const KEY_V1 = Buffer.alloc(32, 0xa1)
const KEY_V2 = Buffer.alloc(32, 0xb2)
const WRONG_KEY = Buffer.alloc(32, 0xff)

function makeService(current = 1): EncryptionService {
  const keys = new Map<number, Buffer>([
    [1, KEY_V1],
    [2, KEY_V2],
  ])
  return new EncryptionService(new StubKeyProvider(keys, current))
}

describe('EncryptionService', () => {
  describe('round-trip', () => {
    it('يفك النص المشفّر ويرجّعه زي ما هو', () => {
      const service = makeService()
      const plain = 'sk_live_51H8xKzExampleSecretKey'

      expect(service.decrypt(service.encrypt(plain))).toBe(plain)
    })

    it('يتعامل مع النص العربي والرموز واليونيكود', () => {
      const service = makeService()
      const plain = 'مفتاح سرّي 🔐 مع رموز: !@#$%^&*()'

      expect(service.decrypt(service.encrypt(plain))).toBe(plain)
    })

    it('يتعامل مع النص الفاضي', () => {
      const service = makeService()

      expect(service.decrypt(service.encrypt(''))).toBe('')
    })

    it('يدّي ناتج مختلف كل مرة لنفس النص (IV عشوائي)', () => {
      const service = makeService()
      const plain = 'same-input'

      expect(service.encrypt(plain)).not.toBe(service.encrypt(plain))
    })
  })

  describe('envelope format', () => {
    it('يكتب رقم إصدار الـ envelope في أول byte', () => {
      const service = makeService()
      const raw = Buffer.from(service.encrypt('x'), 'base64')

      expect(raw.readUInt8(0)).toBe(1)
    })

    it('يكتب نسخة المفتاح الجذري في تاني byte', () => {
      const raw = Buffer.from(makeService(2).encrypt('x'), 'base64')

      expect(raw.readUInt8(1)).toBe(2)
    })

    it('يفك نص اتشفّر بمفتاح متقاعد بعد تدوير المفتاح', () => {
      const encryptedWithV1 = makeService(1).encrypt('old-secret')

      // بعد التدوير: التشفير الجديد بنسخة 2، لكن القديم لازم يفضل مقروء
      const afterRotation = makeService(2)

      expect(afterRotation.decrypt(encryptedWithV1)).toBe('old-secret')
    })

    it('يرفض إصدار envelope غير معروف', () => {
      const service = makeService()
      const raw = Buffer.from(service.encrypt('x'), 'base64')
      raw.writeUInt8(99, 0)

      expect(() => service.decrypt(raw.toString('base64'))).toThrow(
        /إصدار envelope غير معروف/,
      )
    })

    it('يرفض نص أقصر من الحد الأدنى', () => {
      const service = makeService()

      expect(() => service.decrypt(Buffer.alloc(10).toString('base64'))).toThrow(
        /تالف/,
      )
    })
  })

  describe('tamper detection', () => {
    it('يرفض النص لو الـ ciphertext اتعدّل', () => {
      const service = makeService()
      const raw = Buffer.from(service.encrypt('secret-value'), 'base64')

      raw[raw.length - 1] ^= 0xff

      expect(() => service.decrypt(raw.toString('base64'))).toThrow()
    })

    it('يرفض النص لو الـ auth tag اتعدّل', () => {
      const service = makeService()
      const raw = Buffer.from(service.encrypt('secret-value'), 'base64')

      // الـ tag بيبدأ بعد الهيدر (2) والـ IV (12)
      raw[14] ^= 0xff

      expect(() => service.decrypt(raw.toString('base64'))).toThrow()
    })

    it('يرفض النص لو الـ IV اتعدّل', () => {
      const service = makeService()
      const raw = Buffer.from(service.encrypt('secret-value'), 'base64')

      raw[2] ^= 0xff

      expect(() => service.decrypt(raw.toString('base64'))).toThrow()
    })

    it('يرفض النص لو المفتاح غلط', () => {
      const encrypted = makeService().encrypt('secret-value')

      const wrongKeyService = new EncryptionService(
        new StubKeyProvider(new Map([[1, WRONG_KEY]]), 1),
      )

      expect(() => wrongKeyService.decrypt(encrypted)).toThrow()
    })
  })

  describe('json helpers', () => {
    it('يشفّر ويفك object كامل', () => {
      const service = makeService()
      const credentials = {
        api_key: 'pk_test_123',
        secret_key: 'sk_test_456',
        nested: { integration_id: 9876 },
      }

      expect(service.decryptJson(service.encryptJson(credentials))).toEqual(
        credentials,
      )
    })

    it('يرجّع null لو المدخل null أو undefined أو فاضي', () => {
      const service = makeService()

      expect(service.decryptJson(null)).toBeNull()
      expect(service.decryptJson(undefined)).toBeNull()
      expect(service.decryptJson('')).toBeNull()
    })

    it('يرجّع null بدل ما يرمي خطأ لو النص تالف', () => {
      const service = makeService()

      expect(service.decryptJson('not-a-valid-envelope')).toBeNull()
    })
  })
})
