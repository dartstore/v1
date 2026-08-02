import fc from 'fast-check'
import { getCurrency, isSupportedCurrency } from './currency.registry'
import {
  CurrencyMismatchError,
  MoneyError,
  MoneyParseError,
  UnknownCurrencyError,
} from './money.types'
import {
  add,
  allocate,
  allocateEvenly,
  compare,
  deserialize,
  equals,
  format,
  isNegative,
  isZero,
  money,
  multiplyByInteger,
  negate,
  parseDecimal,
  serialize,
  subtract,
  sum,
  toDecimalString,
  toGatewayInteger,
  zero,
} from './money.util'

describe('currency registry', () => {
  it('exposes the correct exponent for zero-decimal currencies', () => {
    expect(getCurrency('JPY').exponent).toBe(0)
    expect(getCurrency('KRW').exponent).toBe(0)
  })

  it('exposes the correct exponent for three-decimal currencies', () => {
    expect(getCurrency('KWD').exponent).toBe(3)
    expect(getCurrency('BHD').exponent).toBe(3)
    expect(getCurrency('OMR').exponent).toBe(3)
  })

  it('exposes the correct exponent for two-decimal currencies', () => {
    expect(getCurrency('USD').exponent).toBe(2)
    expect(getCurrency('EGP').exponent).toBe(2)
    expect(getCurrency('SAR').exponent).toBe(2)
  })

  it('normalizes case and whitespace', () => {
    expect(getCurrency('  usd ').code).toBe('USD')
  })

  it('rejects unknown and malformed codes', () => {
    expect(() => getCurrency('XYZ')).toThrow(UnknownCurrencyError)
    expect(() => getCurrency('US')).toThrow(UnknownCurrencyError)
    expect(() => getCurrency('')).toThrow(UnknownCurrencyError)
    expect(isSupportedCurrency('XYZ')).toBe(false)
  })
})

describe('parseDecimal', () => {
  it('parses two-decimal currencies', () => {
    expect(parseDecimal('10.50', 'USD').amountMinor).toBe(1050n)
    expect(parseDecimal('0.01', 'USD').amountMinor).toBe(1n)
    expect(parseDecimal('1000', 'USD').amountMinor).toBe(100000n)
  })

  it('parses three-decimal currencies without loss', () => {
    expect(parseDecimal('10.500', 'KWD').amountMinor).toBe(10500n)
    expect(parseDecimal('0.001', 'KWD').amountMinor).toBe(1n)
  })

  it('parses zero-decimal currencies', () => {
    expect(parseDecimal('1000', 'JPY').amountMinor).toBe(1000n)
  })

  it('pads short fractions', () => {
    expect(parseDecimal('10.5', 'USD').amountMinor).toBe(1050n)
    expect(parseDecimal('10.5', 'KWD').amountMinor).toBe(10500n)
  })

  it('parses negative amounts', () => {
    expect(parseDecimal('-10.50', 'USD').amountMinor).toBe(-1050n)
  })

  it('normalizes negative zero to zero', () => {
    expect(parseDecimal('-0.00', 'USD').amountMinor).toBe(0n)
    expect(Object.is(parseDecimal('-0.00', 'USD').amountMinor, 0n)).toBe(true)
  })

  it('rejects excess precision rather than truncating silently', () => {
    expect(() => parseDecimal('1.005', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('100.5', 'JPY')).toThrow(MoneyParseError)
    expect(() => parseDecimal('1.0005', 'KWD')).toThrow(MoneyParseError)
  })

  it('rejects exponent notation', () => {
    expect(() => parseDecimal('1e3', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('1E3', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('1.5e-3', 'USD')).toThrow(MoneyParseError)
  })

  it('rejects NaN and Infinity', () => {
    expect(() => parseDecimal('NaN', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('Infinity', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('-Infinity', 'USD')).toThrow(MoneyParseError)
  })

  it('rejects grouping separators and internal whitespace', () => {
    expect(() => parseDecimal('1,000.00', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('1 000.00', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('1_000.00', 'USD')).toThrow(MoneyParseError)
  })

  it('rejects a leading plus sign', () => {
    expect(() => parseDecimal('+10.00', 'USD')).toThrow(MoneyParseError)
  })

  it('rejects non-ASCII digits', () => {
    expect(() => parseDecimal('١٠٫٥٠', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('۱۰.۵۰', 'USD')).toThrow(MoneyParseError)
  })

  it('rejects malformed decimals', () => {
    expect(() => parseDecimal('', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('.', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('.5', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('5.', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('1.2.3', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('abc', 'USD')).toThrow(MoneyParseError)
    expect(() => parseDecimal('--1', 'USD')).toThrow(MoneyParseError)
  })

  it('tolerates surrounding whitespace', () => {
    expect(parseDecimal('  10.50  ', 'USD').amountMinor).toBe(1050n)
  })
})

describe('toDecimalString', () => {
  it('renders each exponent class correctly', () => {
    expect(toDecimalString(money(1050n, 'USD'))).toBe('10.50')
    expect(toDecimalString(money(10500n, 'KWD'))).toBe('10.500')
    expect(toDecimalString(money(1000n, 'JPY'))).toBe('1000')
  })

  it('pads the fractional part', () => {
    expect(toDecimalString(money(5n, 'USD'))).toBe('0.05')
    expect(toDecimalString(money(5n, 'KWD'))).toBe('0.005')
  })

  it('renders negatives', () => {
    expect(toDecimalString(money(-1050n, 'USD'))).toBe('-10.50')
    expect(toDecimalString(money(-5n, 'USD'))).toBe('-0.05')
  })
})

describe('property: parse / render round-trip', () => {
  it('parseDecimal(toDecimalString(m)) === m for every exponent class', () => {
    fc.assert(
      fc.property(
        fc.constantFrom('USD', 'KWD', 'JPY', 'EGP', 'BHD'),
        fc.bigInt({ min: -(10n ** 15n), max: 10n ** 15n }),
        (currency, amountMinor) => {
          const original = money(amountMinor, currency)
          const round = parseDecimal(toDecimalString(original), currency)
          expect(round.amountMinor).toBe(original.amountMinor)
          expect(round.currency).toBe(original.currency)
        },
      ),
      { numRuns: 2000 },
    )
  })
})

describe('arithmetic', () => {
  it('adds and subtracts', () => {
    expect(add(money(1050n, 'USD'), money(50n, 'USD')).amountMinor).toBe(1100n)
    expect(subtract(money(1050n, 'USD'), money(50n, 'USD')).amountMinor).toBe(
      1000n,
    )
  })

  it('rejects cross-currency arithmetic', () => {
    expect(() => add(money(100n, 'USD'), money(100n, 'EGP'))).toThrow(
      CurrencyMismatchError,
    )
    expect(() => subtract(money(100n, 'USD'), money(100n, 'EGP'))).toThrow(
      CurrencyMismatchError,
    )
    expect(() => compare(money(100n, 'USD'), money(100n, 'EGP'))).toThrow(
      CurrencyMismatchError,
    )
  })

  it('multiplies by integers only', () => {
    expect(multiplyByInteger(money(100n, 'USD'), 3).amountMinor).toBe(300n)
    expect(() => multiplyByInteger(money(100n, 'USD'), 1.5)).toThrow(MoneyError)
  })

  it('sums a list', () => {
    expect(
      sum([money(100n, 'USD'), money(250n, 'USD'), money(-50n, 'USD')])
        .amountMinor,
    ).toBe(300n)
  })

  it('sums an empty list only with an explicit currency', () => {
    expect(sum([], 'USD').amountMinor).toBe(0n)
    expect(() => sum([])).toThrow(MoneyError)
  })

  it('compares, negates and inspects', () => {
    expect(compare(money(1n, 'USD'), money(2n, 'USD'))).toBe(-1)
    expect(compare(money(2n, 'USD'), money(2n, 'USD'))).toBe(0)
    expect(negate(money(5n, 'USD')).amountMinor).toBe(-5n)
    expect(isZero(zero('USD'))).toBe(true)
    expect(isNegative(money(-1n, 'USD'))).toBe(true)
    expect(equals(money(1n, 'USD'), money(1n, 'USD'))).toBe(true)
    expect(equals(money(1n, 'USD'), money(1n, 'EGP'))).toBe(false)
  })
})

describe('allocate', () => {
  it('splits evenly when it divides cleanly', () => {
    expect(
      allocateEvenly(money(300n, 'USD'), 3).map((m) => m.amountMinor),
    ).toEqual([100n, 100n, 100n])
  })

  it('distributes the remainder to the earliest largest remainders', () => {
    expect(
      allocateEvenly(money(100n, 'USD'), 3).map((m) => m.amountMinor),
    ).toEqual([34n, 33n, 33n])
  })

  it('handles the classic 0.05 into 3 case', () => {
    expect(allocateEvenly(money(5n, 'USD'), 3).map((m) => m.amountMinor)).toEqual(
      [2n, 2n, 1n],
    )
  })

  it('respects weights', () => {
    expect(allocate(money(1000n, 'USD'), [70n, 30n]).map((m) => m.amountMinor)).toEqual(
      [700n, 300n],
    )
  })

  it('handles weights that do not divide cleanly', () => {
    const parts = allocate(money(1000n, 'USD'), [1n, 1n, 1n])
    expect(parts.map((m) => m.amountMinor)).toEqual([334n, 333n, 333n])
  })

  it('allocates negative amounts (refund reversals) without drift', () => {
    const parts = allocateEvenly(money(-100n, 'USD'), 3)
    expect(parts.map((m) => m.amountMinor)).toEqual([-34n, -33n, -33n])
    expect(sum(parts).amountMinor).toBe(-100n)
  })

  it('handles zero amounts', () => {
    expect(allocateEvenly(zero('USD'), 3).map((m) => m.amountMinor)).toEqual([
      0n,
      0n,
      0n,
    ])
  })

  it('supports a zero weight beneficiary', () => {
    expect(allocate(money(100n, 'USD'), [1n, 0n]).map((m) => m.amountMinor)).toEqual(
      [100n, 0n],
    )
  })

  it('rejects invalid weights', () => {
    expect(() => allocate(money(100n, 'USD'), [])).toThrow(MoneyError)
    expect(() => allocate(money(100n, 'USD'), [0n, 0n])).toThrow(MoneyError)
    expect(() => allocate(money(100n, 'USD'), [-1n, 2n])).toThrow(MoneyError)
    expect(() => allocate(money(100n, 'USD'), [1.5, 1])).toThrow(MoneyError)
    expect(() => allocateEvenly(money(100n, 'USD'), 0)).toThrow(MoneyError)
  })

  it('preserves the currency', () => {
    expect(
      allocateEvenly(money(100n, 'KWD'), 3).every((m) => m.currency === 'KWD'),
    ).toBe(true)
  })
})

describe('property: allocation is loss-free', () => {
  it('the parts always sum exactly to the original amount', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: -(10n ** 12n), max: 10n ** 12n }),
        fc.array(fc.bigInt({ min: 0n, max: 10n ** 6n }), {
          minLength: 1,
          maxLength: 12,
        }),
        (amountMinor, rawWeights) => {
          fc.pre(rawWeights.reduce((a, b) => a + b, 0n) > 0n)

          const original = money(amountMinor, 'USD')
          const parts = allocate(original, rawWeights)

          expect(parts).toHaveLength(rawWeights.length)
          expect(sum(parts, 'USD').amountMinor).toBe(amountMinor)
        },
      ),
      { numRuns: 3000 },
    )
  })

  it('every part shares the sign of the original amount', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 1n, max: 10n ** 12n }),
        fc.integer({ min: 1, max: 10 }),
        (magnitude, parts) => {
          expect(
            allocateEvenly(money(magnitude, 'USD'), parts).every(
              (m) => m.amountMinor >= 0n,
            ),
          ).toBe(true)

          expect(
            allocateEvenly(money(-magnitude, 'USD'), parts).every(
              (m) => m.amountMinor <= 0n,
            ),
          ).toBe(true)
        },
      ),
      { numRuns: 1000 },
    )
  })

  it('no two parts differ by more than one minor unit under equal weights', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: 10n ** 12n }),
        fc.integer({ min: 1, max: 20 }),
        (magnitude, parts) => {
          const values = allocateEvenly(money(magnitude, 'USD'), parts).map(
            (m) => m.amountMinor,
          )
          const smallest = values.reduce((a, b) => (a < b ? a : b))
          const largest = values.reduce((a, b) => (a > b ? a : b))
          expect(largest - smallest <= 1n).toBe(true)
        },
      ),
      { numRuns: 1000 },
    )
  })

  it('allocation is deterministic', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: -(10n ** 9n), max: 10n ** 9n }),
        fc.array(fc.bigInt({ min: 1n, max: 1000n }), {
          minLength: 1,
          maxLength: 8,
        }),
        (amountMinor, weights) => {
          const first = allocate(money(amountMinor, 'USD'), weights)
          const second = allocate(money(amountMinor, 'USD'), weights)
          expect(first.map((m) => m.amountMinor)).toEqual(
            second.map((m) => m.amountMinor),
          )
        },
      ),
      { numRuns: 500 },
    )
  })
})

describe('gateway and transport helpers', () => {
  it('serializes and deserializes losslessly', () => {
    const original = money(123456789012345n, 'USD')
    expect(deserialize(serialize(original)).amountMinor).toBe(
      original.amountMinor,
    )
  })

  it('rejects a malformed serialized amount', () => {
    expect(() => deserialize({ amountMinor: '10.5', currency: 'USD' })).toThrow(
      MoneyParseError,
    )
  })

  it('converts to a gateway integer within the safe range', () => {
    expect(toGatewayInteger(money(1050n, 'USD'))).toBe(1050)
  })

  it('refuses to convert an unsafe amount to a number', () => {
    expect(() => toGatewayInteger(money(2n ** 60n, 'USD'))).toThrow(MoneyError)
  })

  it('rejects unsafe numeric construction', () => {
    expect(() => money(Number.MAX_SAFE_INTEGER + 1, 'USD')).toThrow(MoneyError)
    expect(() => money(1.5, 'USD')).toThrow(MoneyError)
    expect(() => money(NaN, 'USD')).toThrow(MoneyError)
  })
})

describe('format', () => {
  it('groups thousands and appends the symbol', () => {
    expect(format(money(123456789n, 'USD'))).toBe('1,234,567.89 $')
    expect(format(money(123456789n, 'USD'), { withSymbol: false })).toBe(
      '1,234,567.89',
    )
  })

  it('formats zero-decimal and three-decimal currencies', () => {
    expect(format(money(1000n, 'JPY'), { withSymbol: false })).toBe('1,000')
    expect(format(money(1234567n, 'KWD'), { withSymbol: false })).toBe(
      '1,234.567',
    )
  })

  it('formats negatives', () => {
    expect(format(money(-1050n, 'USD'), { withSymbol: false })).toBe('-10.50')
  })
})
