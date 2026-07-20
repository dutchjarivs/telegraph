# Changelog

All notable changes to the `telegraphnet-sdk` Python package. Semantic
versioning; pre-1.0 minor versions add features and stay backward compatible.

## 0.3.0 — unreleased (staged)

> Staged in source; **not yet published** (latest published is 0.2.0). Every
> feature below already works against the hosted relay — publishing 0.3.0 is
> what exposes them through this package.

### Added
- **Attachments.** `send(to, text, attachments=[{"name","mime","data"}])` seals
  files end-to-end; inbox messages carry decoded attachments. Gated on the
  recipient advertising `attachments-v1`.
- **Per-message expiry.** `send(..., expires_at=...)` or `ttl_ms=...` seals an
  advisory, relay-blind expiry; messages expose `expires_at` / `expired`, and
  `inbox(drop_expired=True)` filters them.
- **Idempotency keys.** `send(..., idempotency_key=...)` collapses a retried send
  to the first delivery — no second wire, no second charge. Result carries
  `idempotent`.
- **Signed delivery receipts.** `inbox(receipt=True)` signs a receipt per acked
  wire; `receipts()` fetches them for wires you sent, re-verified against the
  recipient's key (`verified`).
- **Webhooks / push delivery.** `set_webhook(url, secret=...)` / `get_webhook()`
  / `remove_webhook()`, plus a `verify_webhook_signature()` helper to validate
  the `X-Telegraph-Signature` HMAC on your receiver.
- `reply()` forwards all `send()` keywords (attachments, ttl, idempotency_key, …).

### Changed
- **Default server is now the public relay** `https://telegraphnet.com` instead of
  `http://127.0.0.1:7787`. `TelegraphClient(identity=...)` with no server argument now
  joins the public network out of the box; pass a server or set `$TELEGRAPH_SERVER`
  to point at your own relay.

### Fixed
- **Requests to the hosted relay now send a `User-Agent`.** urllib's default
  (`Python-urllib/x.y`) is banned at the edge in front of `telegraphnet.com`
  (Cloudflare `403 error code: 1010`), which made every SDK call fail against the
  hosted relay. The client now sends `telegraph-python/<version>`. No API change.

### Notes
- Backward compatible with 0.2.0 except for the default server above: other
  additions are optional parameters, new result fields, or new methods.
- Large attachments need the operator to raise the relay's ciphertext cap
  (`TELEGRAPH_MAX_CIPHERTEXT_B64`); small attachments work under the default cap.

## 0.2.0

### Added
- **Threading.** `send(..., thread_id=..., reply_to=..., priority=...)` seals
  conversation metadata E2E; `group_threads()` groups messages client-side;
  `reply()` continues a thread. Gated on `wire-envelope-v1`; degrades to a plain
  wire for older peers.

## 0.1.0

- Initial release: `generate_identity()`, `register()`, `send()`, `inbox()`,
  `ack()`, `sent()`, directory search, blocks, reports, credits/pricing, and the
  low-level crypto helpers. Relay-blind — the SDK verifies every record and wire.
