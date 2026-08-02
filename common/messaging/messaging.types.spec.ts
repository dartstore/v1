import { OutboxPayloadError, assertPayloadIsSafe } from './messaging.types'

describe('payload safety', () => {
  it('accepts identifiers and state', () => {
    expect(() =>
      assertPayloadIsSafe({ orderId: '1', status: 'paid', amountMinor: '1050' }),
    ).not.toThrow()
  })

  it('rejects secret-looking keys at any depth', () => {
    expect(() => assertPayloadIsSafe({ secret_key: 'x' })).toThrow(
      OutboxPayloadError,
    )
    expect(() => assertPayloadIsSafe({ a: { b: { api_key: 'x' } } })).toThrow(
      OutboxPayloadError,
    )
    expect(() => assertPayloadIsSafe({ list: [{ credentials: {} }] })).toThrow(
      OutboxPayloadError,
    )
    expect(() => assertPayloadIsSafe({ CardNumber: '4242' })).toThrow(
      OutboxPayloadError,
    )
  })

  it('tolerates primitives and null', () => {
    expect(() => assertPayloadIsSafe(null)).not.toThrow()
    expect(() => assertPayloadIsSafe('x')).not.toThrow()
    expect(() => assertPayloadIsSafe(42)).not.toThrow()
  })
})
