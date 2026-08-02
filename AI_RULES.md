# AI Rules

- Don't rewrite unrelated files.
- Keep current architecture.
- Prefer minimal changes.
- Don't add libraries unless required.
- Explain schema changes before applying them.

## Money handling (Phase 1a — binding)

1. Money is stored as **integer minor units + ISO currency code**.
   `Decimal` is permitted only for the legacy pricing columns pending
   Phase 1b review; never for payment- or ledger-facing values.
2. `parseFloat` / `Number` on a monetary string is prohibited outside
   `src/common/money/money.util.ts`.
3. Balances are **derived from immutable entries**. No `increment` /
   `decrement` on a balance column. `WalletModule` is the single
   grandfathered exception, closed to new callers.
4. Every money-bearing row carries `store_id`, `mode` and `currency`.
5. Arithmetic is defined only between same-currency values; conversion
   is an explicit, recorded operation.
6. Wire-format exponent conversion happens **only** inside gateway
   adapters, reading the exponent from `currency.registry.ts`.

## Outbox discipline (Phase 1a — binding)

The transactional outbox carries **identifiers and state transitions,
never secrets and never full entity snapshots.** A consumer that needs
detail reads it from the source under its own authorization. Without
this rule the outbox becomes a plaintext side-channel around every
access control in the system. `assertPayloadIsSafe` enforces a subset
of this mechanically; the rest is on review.

Messages are written with `OutboxService.emit(tx, ...)` using the
caller's transaction client. Calling it outside a transaction defeats
the entire mechanism.

## Idempotency (Phase 1a — binding)

Uniqueness is enforced by database constraints, never by a
check-then-act in application code. Two concurrent identical requests
must be resolved by the unique index, not by a `findFirst` followed by
a `create`.

## Crypto foundation (frozen)

The envelope format, AAD construction, HKDF derivation and the
`KeyProvider` contract in `src/common/crypto/` are **frozen**. Changes
are permitted only in response to a production bug.

Any table storing AAD-bound ciphertext must use a Postgres
sequence-backed `BigInt` primary key, reserved via
`IdReservationService` **before** encryption. AAD components must be
columns that are immutable for the lifetime of the row.

## Environment variables

Booleans in `.env` accept `true | false | 1 | 0` only. Anything else
fails at boot — `@IsBoolean()` with implicit conversion silently
coerces every string to `true`, so string validation with an allow-list
is used instead.
