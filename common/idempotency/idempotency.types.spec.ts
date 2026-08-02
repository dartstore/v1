import {
  canonicalize,
  fingerprintRequest,
  validateIdempotencyKey,
} from './idempotency.types'

describe('idempotency pure helpers', () => {
  it('canonicalizes objects independently of key order', () => {
    expect(canonicalize({ a: 1, b: 2 })).toBe(canonicalize({ b: 2, a: 1 }))
  })

  it('canonicalizes nested structures deterministically', () => {
    expect(canonicalize({ x: { b: 1, a: 2 }, y: [3, 1] })).toBe(
      canonicalize({ y: [3, 1], x: { a: 2, b: 1 } }),
    )
  })

  it('does not treat arrays as order-independent', () => {
    expect(canonicalize([1, 2])).not.toBe(canonicalize([2, 1]))
  })

  it('handles bigint without throwing', () => {
    expect(canonicalize({ id: 1n })).toBe('{"id":"1"}')
  })

  it('produces a stable fingerprint for reordered bodies', () => {
    const a = fingerprintRequest({
      method: 'post',
      path: '/x',
      body: { a: 1, b: 2 },
    })
    const b = fingerprintRequest({
      method: 'POST',
      path: '/x',
      body: { b: 2, a: 1 },
    })
    expect(a).toBe(b)
  })

  it('produces a different fingerprint for different bodies', () => {
    const a = fingerprintRequest({ method: 'POST', path: '/x', body: { a: 1 } })
    const b = fingerprintRequest({ method: 'POST', path: '/x', body: { a: 2 } })
    expect(a).not.toBe(b)
  })

  it('validates keys', () => {
    expect(validateIdempotencyKey(' abc-123 ')).toBe('abc-123')
    expect(() => validateIdempotencyKey('')).toThrow()
    expect(() => validateIdempotencyKey('a'.repeat(256))).toThrow()
    expect(() => validateIdempotencyKey('has space')).toThrow()
    expect(() => validateIdempotencyKey(123)).toThrow()
  })
})
