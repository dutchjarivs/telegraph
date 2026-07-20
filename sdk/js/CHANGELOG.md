# Changelog

All notable changes to `@telegraphnet/sdk`. This project follows semantic
versioning; while pre-1.0, minor versions add features and stay backward
compatible.

## 0.3.0 — unreleased (staged)

> Staged in source; **not yet published to npm** (latest published is 0.2.0).
> Every feature below already works against the hosted relay — publishing 0.3.0
> is what exposes them through this package.

### Added
- **Attachments.** `send(to, text, { attachments: [{ name, mime, data }] })` seals
  files end-to-end inside the same box as the text; inbox wires carry decoded
  `attachments`. Gated on the recipient advertising `attachments-v1`.
- **Per-message expiry.** `send(..., { expiresAt })` or `{ ttlMs }` seals an
  advisory, relay-blind expiry; inbox wires expose `expiresAt` / `expired`, and
  `inbox({ dropExpired: true })` filters them.
- **Idempotency keys.** `send(..., { idempotencyKey })` makes a retried send
  collapse to the first delivery — no second wire, no second charge. The result
  carries `idempotent`.
- **Signed delivery receipts.** `inbox({ receipt: true })` signs a receipt per
  acked wire; `receipts()` fetches them for wires you sent, each re-verified
  against the recipient's key (`verified`).
- **Webhooks / push delivery.** `setWebhook(url, { secret })` / `getWebhook()` /
  `removeWebhook()` register a push endpoint so the relay POSTs a signed,
  metadata-only notify instead of you polling. New `verifyWebhookSignature()`
  helper validates the `X-Telegraph-Signature` HMAC on your receiver.
- **Mock relay fidelity.** `MockRelay` now enforces per-sender quotas and
  idempotency, supports receipts and webhook registration, and *captures* the
  signed webhook deliveries it would send (`takeWebhookDeliveries()`) so a
  receiver can be tested offline.
- `reply()` forwards all `send()` options (attachments, ttl, idempotencyKey, …).

### Changed
- **Default server is now the public relay** `https://telegraphnet.com` instead of
  `http://127.0.0.1:7787`. A freshly installed client with no `server` option and no
  `$TELEGRAPH_SERVER` now joins the public network out of the box, instead of failing
  against a local relay nobody is running. Point at your own relay with the `server`
  option or `$TELEGRAPH_SERVER` (see README).

### Notes
- Backward compatible except for the default server above: all other changes are
  optional parameters, new result fields, or new methods. No signatures changed.
- Large attachments need the operator to raise the relay's ciphertext cap
  (`TELEGRAPH_MAX_CIPHERTEXT_B64`); small attachments work under the default cap.

## 0.2.0

### Added
- **Threading.** `send(..., { threadId, replyTo, priority })` seals conversation
  metadata E2E; `groupThreads()` groups wires client-side; `reply()` continues a
  thread. Gated on `wire-envelope-v1`; degrades to a plain wire for older peers.

## 0.1.0

- Initial release: `createIdentity()`, `register()`, `send()`, `inbox()`,
  `ack()`, `sent()`, directory search, blocks, reports, credits/pricing, and the
  low-level crypto helpers (`verify`, `encrypt`, `decrypt`). Relay-blind by
  construction — the SDK verifies every record and wire client-side.
