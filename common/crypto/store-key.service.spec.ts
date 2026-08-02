import {
  DecryptionError,
  EncryptionContext,
  EnvelopeScope,
  KeyProvider,
  computeKeyCheckValue,
} from './key-provider.interface'
import { StoreKeyService } from './store-key.service'

class StubKeyProvider implements KeyProvider {
  constructor(
    private readonly keys: Map<number, Buffer>,
    private readonly current: number,
  ) {}

  async currentKekVersion(): Promise<number> {
    return this.current
  }

  async getKek(version: number): Promise<Buffer> {
    const key = this.keys.get(version)
    if (!key) throw new Error(`مفتاح نسخة ${version} مش متاح`)
    return Buffer.from(key)
  }

  async availableVersions(): Promise<number[]> {
    return [...this.keys.keys()].sort((a, b) => a - b)
  }

  async keyCheckValue(version: number): Promise<string> {
    return computeKeyCheckValue(await this.getKek(version))
  }
}

const KEK_V1 = Buffer.alloc(32, 0xa1)
const KEK_V2 = Buffer.alloc(32, 0xb2)

function makeService(current = 1): StoreKeyService {
  const keys = new Map<number, Buffer>([
    [1, KEK_V1],
    [2, KEK_V2],
    [400, Buffer.alloc(32, 0xd4)],
  ])
  return new StoreKeyService(new StubKeyProvider(keys, current))
}

const CTX: EncryptionContext = {
  mode: 'live',
  recordType: 'payment_account',
  recordId: '7',
  field: 'credentials',
}

describe('StoreKeyService', () => {
  describe('key derivation', () => {
    it('حتمية — نفس المدخلات نفس المفتاح', async () => {
      const service = makeService()

      expect(await service.deriveStoreKey(42n)).toEqual(
        await service.deriveStoreKey(42n),
      )
    })

    it('طول المفتاح 32 byte', async () => {
      expect(await makeService().deriveStoreKey(1n)).toHaveLength(32)
    })

    it('مفاتيح مختلفة لمتاجر مختلفة', async () => {
      const service = makeService()

      expect(await service.deriveStoreKey(1n)).not.toEqual(
        await service.deriveStoreKey(2n),
      )
    })

    it('مفاتيح مختلفة لنسخ dek مختلفة', async () => {
      const service = makeService()

      expect(await service.deriveStoreKey(1n, 1)).not.toEqual(
        await service.deriveStoreKey(1n, 2),
      )
    })

    it('مفاتيح مختلفة لنسخ kek مختلفة', async () => {
      const service = makeService()

      expect(await service.deriveStoreKey(1n, 1, 1)).not.toEqual(
        await service.deriveStoreKey(1n, 1, 2),
      )
    })
  })

  /* R5 — التوحيد العددي لمعرّف المتجر */
  describe('store id normalization (R5)', () => {
    it('BigInt و number و string بيدّوا نفس المفتاح', async () => {
      const service = makeService()
      const expected = await service.deriveStoreKey(42n)

      expect(await service.deriveStoreKey(42)).toEqual(expected)
      expect(await service.deriveStoreKey('42')).toEqual(expected)
    })

    it('"042" بتدّي نفس مفتاح 42', async () => {
      const service = makeService()

      expect(await service.deriveStoreKey('042')).toEqual(
        await service.deriveStoreKey(42n),
      )
    })

    it('بيشيل الفراغات', async () => {
      const service = makeService()

      expect(await service.deriveStoreKey('  42  ')).toEqual(
        await service.deriveStoreKey(42n),
      )
    })

    it('بيرفض المعرّف غير الرقمي والفاضي والسالب', async () => {
      const service = makeService()

      await expect(service.deriveStoreKey('abc')).rejects.toThrow(/store_id/)
      await expect(service.deriveStoreKey('  ')).rejects.toThrow(/store_id/)
      await expect(service.deriveStoreKey(-1n)).rejects.toThrow(/سالب/)
      await expect(service.deriveStoreKey(1.5)).rejects.toThrow(/صحيح/)
    })
  })

  /* الطبقة الأولى — العزل بين المتاجر */
  describe('cross-tenant isolation', () => {
    it('متجر مايقدرش يفك تشفير بيانات متجر تاني', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'store-1-key', CTX)

      await expect(
        service.decryptForStore(2n, envelope.payload, CTX),
      ).rejects.toMatchObject({ reason: 'integrity' })
    })

    it('decryptJsonForStore بترمي — مش ترجّع null — لو المتجر غلط', async () => {
      const service = makeService()
      const envelope = await service.encryptJsonForStore(
        1n,
        { api_key: 'x' },
        CTX,
      )

      await expect(
        service.decryptJsonForStore(2n, envelope.payload, CTX),
      ).rejects.toMatchObject({ reason: 'integrity' })
    })
  })

  /* B1 — الطبقة التانية: العزل جوه المتجر الواحد */
  describe('intra-tenant isolation via AAD (B1)', () => {
    it('نص وضع test مايتفكش كنص وضع live', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'test-key', {
        ...CTX,
        mode: 'test',
      })

      await expect(
        service.decryptForStore(1n, envelope.payload, {
          ...CTX,
          mode: 'live',
        }),
      ).rejects.toMatchObject({ reason: 'integrity' })
    })

    it('نص منقول من صف لصف تاني بيفشل', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'account-7-key', {
        ...CTX,
        recordId: '7',
      })

      await expect(
        service.decryptForStore(1n, envelope.payload, {
          ...CTX,
          recordId: '8',
        }),
      ).rejects.toMatchObject({ reason: 'integrity' })
    })

    it('نص منقول من حقل لحقل تاني بيفشل', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'secret', {
        ...CTX,
        field: 'credentials',
      })

      await expect(
        service.decryptForStore(1n, envelope.payload, {
          ...CTX,
          field: 'webhook_secret',
        }),
      ).rejects.toMatchObject({ reason: 'integrity' })
    })

    it('نص منقول من نوع كيان لنوع تاني بيفشل', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'secret', CTX)

      await expect(
        service.decryptForStore(1n, envelope.payload, {
          ...CTX,
          recordType: 'webhook_endpoint',
        }),
      ).rejects.toMatchObject({ reason: 'integrity' })
    })
  })

  describe('round-trip', () => {
    it('بيفك النص لنفس المتجر ونفس السياق', async () => {
      const service = makeService()
      const plain = 'sk_live_paymob_integration_secret'
      const envelope = await service.encryptForStore(7n, plain, CTX)

      expect(await service.decryptForStore(7n, envelope.payload, CTX)).toBe(
        plain,
      )
    })

    it('بيتعامل مع بيانات اعتماد كاملة كـ JSON', async () => {
      const service = makeService()
      const credentials = {
        api_key: 'pk_live_abc',
        secret_key: 'sk_live_def',
        integration_id: 123456,
        hmac_secret: 'hmac_ghi',
      }

      const envelope = await service.encryptJsonForStore(9n, credentials, CTX)

      expect(
        await service.decryptJsonForStore(9n, envelope.payload, CTX),
      ).toEqual(credentials)
    })

    it('ناتج مختلف كل مرة (IV عشوائي)', async () => {
      const service = makeService()

      expect((await service.encryptForStore(1n, 'x', CTX)).payload).not.toBe(
        (await service.encryptForStore(1n, 'x', CTX)).payload,
      )
    })

    it('بيرجّع null للمدخل الفاضي', async () => {
      const service = makeService()

      await expect(
        service.decryptJsonForStore(1n, null, CTX),
      ).resolves.toBeNull()
      await expect(service.decryptJsonForStore(1n, '', CTX)).resolves.toBeNull()
    })
  })

  /* B4 — اتساع حقول النسخ */
  describe('key version width (B4)', () => {
    it('بيشتغل مع kek_version أكبر من 255', async () => {
      const service = makeService(400)
      const envelope = await service.encryptForStore(1n, 'secret', CTX)

      expect(envelope.kekVersion).toBe(400)
      expect(await service.decryptForStore(1n, envelope.payload, CTX)).toBe(
        'secret',
      )
    })

    it('بيشتغل مع dek_version أكبر من 255', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'secret', CTX, 1000)

      expect(envelope.dekVersion).toBe(1000)
      expect(await service.decryptForStore(1n, envelope.payload, CTX)).toBe(
        'secret',
      )
    })

    it('بيقبل الحد الأقصى 65535', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'x', CTX, 65535)

      expect(await service.decryptForStore(1n, envelope.payload, CTX)).toBe('x')
    })

    it('بيرفض نسخة خارج المدى', async () => {
      const service = makeService()

      await expect(service.deriveStoreKey(1n, 0)).rejects.toThrow(/dek_version/)
      await expect(service.deriveStoreKey(1n, 65536)).rejects.toThrow(
        /dek_version/,
      )
    })
  })

  describe('envelope metadata', () => {
    it('بيرجّع نسخ المفاتيح مع الناتج', async () => {
      const envelope = await makeService(2).encryptForStore(1n, 'x', CTX, 3)

      expect(envelope.kekVersion).toBe(2)
      expect(envelope.dekVersion).toBe(3)
    })

    it('readEnvelopeHeader بتقرا الهيدر من غير فك تشفير', async () => {
      const service = makeService(2)
      const envelope = await service.encryptForStore(1n, 'x', CTX, 3)

      expect(service.readEnvelopeHeader(envelope.payload)).toEqual({
        envelopeVersion: 1,
        scope: EnvelopeScope.Store,
        kekVersion: 2,
        dekVersion: 3,
      })
    })

    it('بيفك نص اتشفّر بنسخة kek قديمة بعد التدوير', async () => {
      const envelope = await makeService(1).encryptForStore(5n, 'old', CTX)

      expect(await makeService(2).decryptForStore(5n, envelope.payload, CTX)).toBe(
        'old',
      )
    })

    it('بيرفض envelope نطاقه المنصة', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'x', CTX)
      const raw = Buffer.from(envelope.payload, 'base64')
      raw.writeUInt8(EnvelopeScope.Platform, 1)

      await expect(
        service.decryptForStore(1n, raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'malformed' })
    })

    it('بيرفض إصدار envelope غير معروف', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'x', CTX)
      const raw = Buffer.from(envelope.payload, 'base64')
      raw.writeUInt8(99, 0)

      await expect(
        service.decryptForStore(1n, raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'unsupported_version' })
    })
  })

  describe('tamper detection', () => {
    it('بيبلّغ integrity لو الـ ciphertext اتعدّل', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'secret', CTX)
      const raw = Buffer.from(envelope.payload, 'base64')
      raw[raw.length - 1] ^= 0xff

      await expect(
        service.decryptForStore(1n, raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'integrity', isSecurityRelevant: true })
    })

    it('بيبلّغ integrity لو الـ dek_version اتعدّل', async () => {
      const service = makeService()
      const envelope = await service.encryptForStore(1n, 'secret', CTX)
      const raw = Buffer.from(envelope.payload, 'base64')
      raw.writeUInt16BE(7, 4)

      await expect(
        service.decryptForStore(1n, raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'integrity' })
    })

    it('بيبلّغ key_unavailable لو نسخة المفتاح مش موجودة', async () => {
      const service = new StoreKeyService(
        new StubKeyProvider(new Map([[1, KEK_V1]]), 1),
      )
      const envelope = await service.encryptForStore(1n, 'x', CTX)
      const raw = Buffer.from(envelope.payload, 'base64')
      raw.writeUInt16BE(99, 2)

      await expect(
        service.decryptForStore(1n, raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'key_unavailable' })
    })
  })
})
