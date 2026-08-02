import * as crypto from 'crypto'
import {
  DecryptionError,
  EncryptionContext,
  EnvelopeScope,
  KeyProvider,
  computeKeyCheckValue,
} from './key-provider.interface'
import { EncryptionService, PLATFORM_KEY_VERSION } from './encryption.service'

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
const WRONG_KEK = Buffer.alloc(32, 0xff)

function makeService(current = 1): EncryptionService {
  const keys = new Map<number, Buffer>([
    [1, KEK_V1],
    [2, KEK_V2],
    [300, Buffer.alloc(32, 0xc3)],
  ])
  return new EncryptionService(new StubKeyProvider(keys, current))
}

const CTX: EncryptionContext = {
  mode: 'live',
  recordType: 'platform_secret',
  recordId: '1',
  field: 'value',
}

describe('EncryptionService', () => {
  describe('round-trip', () => {
    it('يفك النص ويرجّعه زي ما هو', async () => {
      const service = makeService()
      const plain = 'sk_live_51H8xKzExampleSecretKey'

      expect(await service.decrypt(await service.encrypt(plain, CTX), CTX)).toBe(
        plain,
      )
    })

    it('يتعامل مع اليونيكود والرموز', async () => {
      const service = makeService()
      const plain = 'مفتاح سرّي 🔐 !@#$%^&*()'

      expect(await service.decrypt(await service.encrypt(plain, CTX), CTX)).toBe(
        plain,
      )
    })

    it('يتعامل مع النص الفاضي', async () => {
      const service = makeService()

      expect(await service.decrypt(await service.encrypt('', CTX), CTX)).toBe('')
    })

    it('يدّي ناتج مختلف كل مرة (IV عشوائي)', async () => {
      const service = makeService()

      expect(await service.encrypt('same', CTX)).not.toBe(
        await service.encrypt('same', CTX),
      )
    })
  })

  /* B3 — المفتاح الجذري مايتستخدمش كمفتاح تشفير */
  describe('platform key derivation (B3)', () => {
    it('مايستخدمش الـ KEK كمفتاح AES مباشرةً', async () => {
      const service = makeService()
      const envelope = Buffer.from(await service.encrypt('probe', CTX), 'base64')

      const iv = envelope.subarray(6, 18)
      const tag = envelope.subarray(18, 34)
      const ciphertext = envelope.subarray(34)

      // لو الـ KEK كان هو مفتاح التشفير، الفك بيه كان هينجح.
      const decipher = crypto.createDecipheriv('aes-256-gcm', KEK_V1, iv)
      decipher.setAAD(Buffer.alloc(0))
      decipher.setAuthTag(tag)

      expect(() =>
        Buffer.concat([decipher.update(ciphertext), decipher.final()]),
      ).toThrow()
    })

    it('يكتب نسخة مفتاح المنصة في الـ envelope', async () => {
      const raw = Buffer.from(await makeService().encrypt('x', CTX), 'base64')

      expect(raw.readUInt16BE(4)).toBe(PLATFORM_KEY_VERSION)
    })
  })

  /* B1 — الربط بالسياق */
  describe('AAD binding (B1)', () => {
    it('يفشل لو الـ mode اتغيّر', async () => {
      const service = makeService()
      const payload = await service.encrypt('secret', { ...CTX, mode: 'test' })

      await expect(
        service.decrypt(payload, { ...CTX, mode: 'live' }),
      ).rejects.toThrow(DecryptionError)
    })

    it('يفشل لو recordId اتغيّر', async () => {
      const service = makeService()
      const payload = await service.encrypt('secret', { ...CTX, recordId: '1' })

      await expect(
        service.decrypt(payload, { ...CTX, recordId: '2' }),
      ).rejects.toThrow(DecryptionError)
    })

    it('يفشل لو recordType اتغيّر', async () => {
      const service = makeService()
      const payload = await service.encrypt('secret', CTX)

      await expect(
        service.decrypt(payload, { ...CTX, recordType: 'other' }),
      ).rejects.toThrow(DecryptionError)
    })

    it('يفشل لو اسم الحقل اتغيّر', async () => {
      const service = makeService()
      const payload = await service.encrypt('secret', CTX)

      await expect(
        service.decrypt(payload, { ...CTX, field: 'other' }),
      ).rejects.toThrow(DecryptionError)
    })

    it('الترميز بطول مسبوق بيمنع الالتباس بين العناصر', async () => {
      const service = makeService()

      // "ab|c" و "ab" + "c" ماينفعش يدّوا نفس الـ AAD
      const payload = await service.encrypt('secret', {
        ...CTX,
        recordType: 'ab',
        recordId: 'c',
      })

      await expect(
        service.decrypt(payload, { ...CTX, recordType: 'abc', recordId: '' }),
      ).rejects.toThrow()
    })

    it('يرفض سياق ناقص', async () => {
      const service = makeService()

      await expect(
        service.encrypt('x', { ...CTX, recordId: '' }),
      ).rejects.toThrow(/recordId مطلوب/)
    })

    it('يرفض mode غير صالح', async () => {
      const service = makeService()

      await expect(
        service.encrypt('x', { ...CTX, mode: 'staging' as any }),
      ).rejects.toThrow(/mode/)
    })
  })

  /* B4 — اتساع حقول النسخ */
  describe('key version width (B4)', () => {
    it('يشتغل مع نسخة مفتاح أكبر من 255', async () => {
      const service = makeService(300)
      const payload = await service.encrypt('secret', CTX)
      const raw = Buffer.from(payload, 'base64')

      expect(raw.readUInt16BE(2)).toBe(300)
      expect(await service.decrypt(payload, CTX)).toBe('secret')
    })
  })

  describe('envelope format', () => {
    it('يكتب رقم إصدار الـ envelope في أول byte', async () => {
      const raw = Buffer.from(await makeService().encrypt('x', CTX), 'base64')

      expect(raw.readUInt8(0)).toBe(1)
    })

    it('يكتب نطاق المنصة في تاني byte', async () => {
      const raw = Buffer.from(await makeService().encrypt('x', CTX), 'base64')

      expect(raw.readUInt8(1)).toBe(EnvelopeScope.Platform)
    })

    it('يرفض envelope نطاقه متجر', async () => {
      const service = makeService()
      const raw = Buffer.from(await service.encrypt('x', CTX), 'base64')
      raw.writeUInt8(EnvelopeScope.Store, 1)

      await expect(
        service.decrypt(raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'malformed' })
    })

    it('يرفض إصدار envelope غير معروف', async () => {
      const service = makeService()
      const raw = Buffer.from(await service.encrypt('x', CTX), 'base64')
      raw.writeUInt8(99, 0)

      await expect(
        service.decrypt(raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'unsupported_version' })
    })

    it('يرفض نص أقصر من الحد الأدنى', async () => {
      await expect(
        makeService().decrypt(Buffer.alloc(10).toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'malformed' })
    })

    it('يفك نص اتشفّر بمفتاح متقاعد بعد التدوير', async () => {
      const encryptedWithV1 = await makeService(1).encrypt('old-secret', CTX)

      expect(await makeService(2).decrypt(encryptedWithV1, CTX)).toBe(
        'old-secret',
      )
    })

    it('يبلّغ key_unavailable لو المفتاح مش موجود', async () => {
      const service = new EncryptionService(
        new StubKeyProvider(new Map([[1, KEK_V1]]), 1),
      )
      const raw = Buffer.from(await service.encrypt('x', CTX), 'base64')
      raw.writeUInt16BE(99, 2)

      await expect(
        service.decrypt(raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'key_unavailable' })
    })
  })

  /* R2 — التمييز بين الفشل العادي وانتهاك السلامة */
  describe('tamper detection (R2)', () => {
    it('يبلّغ integrity لو الـ ciphertext اتعدّل', async () => {
      const service = makeService()
      const raw = Buffer.from(await service.encrypt('secret', CTX), 'base64')
      raw[raw.length - 1] ^= 0xff

      await expect(
        service.decrypt(raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'integrity', isSecurityRelevant: true })
    })

    it('يبلّغ integrity لو الـ auth tag اتعدّل', async () => {
      const service = makeService()
      const raw = Buffer.from(await service.encrypt('secret', CTX), 'base64')
      raw[18] ^= 0xff

      await expect(
        service.decrypt(raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'integrity' })
    })

    it('يبلّغ integrity لو الـ IV اتعدّل', async () => {
      const service = makeService()
      const raw = Buffer.from(await service.encrypt('secret', CTX), 'base64')
      raw[6] ^= 0xff

      await expect(
        service.decrypt(raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'integrity' })
    })

    it('يبلّغ integrity لو المفتاح غلط', async () => {
      const payload = await makeService().encrypt('secret', CTX)
      const wrongKeyService = new EncryptionService(
        new StubKeyProvider(new Map([[1, WRONG_KEK]]), 1),
      )

      await expect(wrongKeyService.decrypt(payload, CTX)).rejects.toMatchObject({
        reason: 'integrity',
      })
    })
  })

  describe('json helpers', () => {
    it('يشفّر ويفك object كامل', async () => {
      const service = makeService()
      const value = { api_key: 'pk_test_123', nested: { id: 9876 } }

      expect(
        await service.decryptJson(await service.encryptJson(value, CTX), CTX),
      ).toEqual(value)
    })

    it('يرجّع null للمدخل الفاضي', async () => {
      const service = makeService()

      await expect(service.decryptJson(null, CTX)).resolves.toBeNull()
      await expect(service.decryptJson(undefined, CTX)).resolves.toBeNull()
      await expect(service.decryptJson('', CTX)).resolves.toBeNull()
    })

    it('يرمي — مش يرجّع null — لو في عبث', async () => {
      const service = makeService()
      const raw = Buffer.from(await service.encryptJson({ a: 1 }, CTX), 'base64')
      raw[raw.length - 1] ^= 0xff

      await expect(
        service.decryptJson(raw.toString('base64'), CTX),
      ).rejects.toMatchObject({ reason: 'integrity' })
    })
  })

  /* R1 — نسخ دفاعية من مادة المفتاح */
  describe('defensive key copies (R1)', () => {
    it('تعديل المفتاح الراجع مايأثرش على العمليات اللي بعده', async () => {
      const provider = new StubKeyProvider(new Map([[1, KEK_V1]]), 1)
      const service = new EncryptionService(provider)

      const leaked = await provider.getKek(1)
      leaked.fill(0)

      expect(await service.decrypt(await service.encrypt('x', CTX), CTX)).toBe(
        'x',
      )
    })
  })
})
