import { KeyProvider } from './key-provider.interface'
import { StoreKeyService } from './store-key.service'

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

const KEK_V1 = Buffer.alloc(32, 0xa1)
const KEK_V2 = Buffer.alloc(32, 0xb2)

function makeService(current = 1): StoreKeyService {
  const keys = new Map<number, Buffer>([
    [1, KEK_V1],
    [2, KEK_V2],
  ])
  return new StoreKeyService(new StubKeyProvider(keys, current))
}

describe('StoreKeyService', () => {
  describe('key derivation', () => {
    it('بيدّي نفس المفتاح لنفس المدخلات', () => {
      const service = makeService()

      expect(service.deriveStoreKey(42n)).toEqual(service.deriveStoreKey(42n))
    })

    it('بيدّي مفتاح طوله 32 byte', () => {
      expect(makeService().deriveStoreKey(1n)).toHaveLength(32)
    })

    it('بيوحّد شكل المعرّف بين BigInt و number و string', () => {
      const service = makeService()

      expect(service.deriveStoreKey(42n)).toEqual(service.deriveStoreKey(42))
      expect(service.deriveStoreKey(42n)).toEqual(service.deriveStoreKey('42'))
    })

    it('بيدّي مفاتيح مختلفة لمتاجر مختلفة', () => {
      const service = makeService()

      expect(service.deriveStoreKey(1n)).not.toEqual(service.deriveStoreKey(2n))
    })

    it('بيدّي مفاتيح مختلفة لنسخ dek مختلفة لنفس المتجر', () => {
      const service = makeService()

      expect(service.deriveStoreKey(1n, 1)).not.toEqual(
        service.deriveStoreKey(1n, 2),
      )
    })

    it('بيدّي مفاتيح مختلفة لنسخ kek مختلفة لنفس المتجر', () => {
      const service = makeService()

      expect(service.deriveStoreKey(1n, 1, 1)).not.toEqual(
        service.deriveStoreKey(1n, 1, 2),
      )
    })

    it('بيرفض المعرّف الفاضي', () => {
      expect(() => makeService().deriveStoreKey('  ')).toThrow(/store_id مطلوب/)
    })

    it('بيرفض نسخة dek خارج المدى المسموح', () => {
      const service = makeService()

      expect(() => service.deriveStoreKey(1n, 0)).toThrow(/dek_version/)
      expect(() => service.deriveStoreKey(1n, 256)).toThrow(/dek_version/)
    })
  })

  describe('tenant isolation', () => {
    it('متجر مايقدرش يفك تشفير بيانات متجر تاني', () => {
      const service = makeService()
      const envelope = service.encryptForStore(1n, 'store-1-api-key')

      expect(() => service.decryptForStore(2n, envelope.payload)).toThrow()
    })

    it('decryptJsonForStore بترجّع null بدل ما ترمي لو المتجر غلط', () => {
      const service = makeService()
      const envelope = service.encryptJsonForStore(1n, { api_key: 'x' })

      expect(service.decryptJsonForStore(2n, envelope.payload)).toBeNull()
    })
  })

  describe('round-trip', () => {
    it('بيفك النص المشفّر لنفس المتجر', () => {
      const service = makeService()
      const plain = 'sk_live_paymob_integration_secret'
      const envelope = service.encryptForStore(7n, plain)

      expect(service.decryptForStore(7n, envelope.payload)).toBe(plain)
    })

    it('بيتعامل مع بيانات اعتماد كاملة كـ JSON', () => {
      const service = makeService()
      const credentials = {
        api_key: 'pk_live_abc',
        secret_key: 'sk_live_def',
        integration_id: 123456,
        hmac_secret: 'hmac_ghi',
      }

      const envelope = service.encryptJsonForStore(9n, credentials)

      expect(service.decryptJsonForStore(9n, envelope.payload)).toEqual(
        credentials,
      )
    })

    it('بيدّي ناتج مختلف كل مرة لنفس المدخلات (IV عشوائي)', () => {
      const service = makeService()

      expect(service.encryptForStore(1n, 'x').payload).not.toBe(
        service.encryptForStore(1n, 'x').payload,
      )
    })
  })

  describe('envelope metadata', () => {
    it('بيرجّع نسخ المفاتيح المستخدمة مع الناتج', () => {
      const envelope = makeService(2).encryptForStore(1n, 'x', 3)

      expect(envelope.kekVersion).toBe(2)
      expect(envelope.dekVersion).toBe(3)
    })

    it('readEnvelopeVersions بتقرا النسخ من غير فك تشفير', () => {
      const envelope = makeService(2).encryptForStore(1n, 'x', 3)

      expect(makeService(2).readEnvelopeVersions(envelope.payload)).toEqual({
        envelopeVersion: 1,
        kekVersion: 2,
        dekVersion: 3,
      })
    })

    it('بيفك نص اتشفّر بنسخة kek قديمة بعد التدوير', () => {
      const envelope = makeService(1).encryptForStore(5n, 'old-secret')
      const afterRotation = makeService(2)

      expect(afterRotation.decryptForStore(5n, envelope.payload)).toBe(
        'old-secret',
      )
    })

    it('بيرفض إصدار envelope غير معروف', () => {
      const service = makeService()
      const raw = Buffer.from(
        service.encryptForStore(1n, 'x').payload,
        'base64',
      )
      raw.writeUInt8(99, 0)

      expect(() => service.decryptForStore(1n, raw.toString('base64'))).toThrow(
        /إصدار envelope غير معروف/,
      )
    })
  })

  describe('tamper detection', () => {
    it('بيرفض النص لو الـ ciphertext اتعدّل', () => {
      const service = makeService()
      const raw = Buffer.from(
        service.encryptForStore(1n, 'secret').payload,
        'base64',
      )

      raw[raw.length - 1] ^= 0xff

      expect(() => service.decryptForStore(1n, raw.toString('base64'))).toThrow()
    })

    it('بيرفض النص لو الـ dek_version اتعدّل', () => {
      const service = makeService()
      const raw = Buffer.from(
        service.encryptForStore(1n, 'secret').payload,
        'base64',
      )

      raw.writeUInt8(7, 2)

      expect(() => service.decryptForStore(1n, raw.toString('base64'))).toThrow()
    })
  })
})
