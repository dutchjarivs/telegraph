# Roadmap designs — deferred item-3 features

These are the messaging features from @darling's feedback (mandate item 3) that I
**deliberately did not build unsupervised** on the night of 2026-07-14, because
each one changes either the wire format across every SDK, the crypto, or the
relay's outbound network behavior — decisions that should be Tristan's, not made
at 2am on a live relay with real third-party users. Each has a concrete design
here so approving it is a green-light, not a fresh start.

Shipped that night instead (all additive, backward-compatible, tested): idempotency
keys, operator audit trail, dashboard metrics, recipient allowlists.

---

## 1. Thread / conversation IDs + reply-to + priority

**Why deferred:** the message signature covers a fixed field list
`[tag, to, from, nonce, ciphertext, ts]`. Adding `threadId`/`replyTo`/`priority`
as *signed* fields is a v2 envelope format that old relays and old clients reject
(`bad_signature`). Adding them *unsigned* leaves them relay-mutable. The clean
answer changes the **plaintext** format every SDK produces — an ecosystem
decision.

**Recommended design — E2E-in-plaintext, capability-gated:**
- The plaintext sealed in the box becomes a versioned JSON envelope:
  `{"v":1,"text":"…","threadId":"…?","replyTo":"messageId?","priority":"normal|high?"}`.
  Threading metadata is then end-to-end encrypted and authenticated (the box
  already authenticates it) and the relay stays blind — no relay change, no
  signature change.
- **Backward compatibility** is the whole problem. An old receiver handed a JSON
  envelope would show raw JSON. Solution: advertise support in the directory
  record's `capabilities` (e.g. `"wire-envelope-v1"`). A sender wraps in the
  envelope **only** when the recipient advertises the capability; otherwise it
  sends a bare string as today. Receivers parse defensively: JSON with a numeric
  `v` and string `text` → envelope; anything else → treat the whole payload as
  `text` (the current behavior).
- `threadId` is a client-chosen opaque string (a ULID or a hash of the first
  message id). `replyTo` is a prior wire's `id`. `priority` is advisory — the
  relay never sees it; clients use it to sort.
- SDK surface: `send(to, text, { threadId, replyTo, priority })`; `inbox()`
  returns `{ …, threadId, replyTo, priority }` (nulls when absent). A helper
  `reply(wire, text)` copies `threadId` and sets `replyTo = wire.id`.

**Effort:** medium. Touches both SDKs + docs, plus a capability bit. No relay
change, no crypto change. Ship in one coordinated SDK minor version.

**Open question for Tristan:** OK to make the plaintext a versioned JSON envelope
(gated on the capability so nothing breaks), or keep wires as opaque strings and
push threading entirely into application payloads?

---

## 2. Webhooks / push delivery

**Why deferred (flagged 2026-07-13 too):** this is the one feature that makes the
relay open **outbound** connections to attacker-supplied URLs — classic SSRF,
and the relay sits behind a Cloudflare tunnel on Tristan's network. Doable
safely, but it earns a careful review, not a 2am merge.

**Recommended design — notify-only, hardened:**
- Per-agent registered callback URL (signed registration, like everything else).
- The webhook payload carries **no ciphertext** — only `{event:"wire.received",
  to, from, id, ts}`. It's a doorbell: the agent still calls `GET /v1/inbox` to
  fetch and decrypt. This means a mis-delivered or intercepted webhook leaks only
  metadata that the recipient already gets, never message content.
- SSRF defense, all mandatory: **https only**; resolve the host and **refuse
  private/loopback/link-local/ULA ranges** (10/8, 172.16/12, 192.168/16, 127/8,
  169.254/16, ::1, fc00::/7) — re-checked against the resolved IP, not just the
  hostname, to beat DNS rebinding; **no redirects**; hard connect+read timeout
  (~3s); a response body cap; and a per-URL circuit breaker.
- Signed payloads: an `X-Telegraph-Signature` HMAC (or Ed25519 over the body with
  the relay's key) so the receiver can verify the call is really from the relay.
- Retries with capped exponential backoff and a dead-letter after N failures;
  failures visible in `admin-overview` and to the agent.
- Long-poll (`inbox?wait=`) stays the default and the recommendation — it works
  behind NAT and needs no inbound URL. Webhooks are for agents with a public
  endpoint that want to avoid holding a connection.

**Effort:** medium-high, mostly the SSRF hardening and its tests. **Do not ship
without a dedicated review of the private-range/rebinding defense.**

**Open question for Tristan:** confirm notify-only (no ciphertext in the webhook)
and that we require https + private-range blocking with no exceptions.

---

## 3. Key rotation

**Why deferred:** crypto-identity surgery. Get it subtly wrong and you either
lock an agent out or accept forged rotations. Same class of "worse-than-nothing
if broken" risk as the double-ratchet gap — not an unsupervised job.

**Recommended design — signing key as root, box key rotatable:**
- The **signing key stays the identity root** (the address derives from it; that
  never changes). The **box (encryption) key becomes rotatable**: the agent
  publishes a new `boxPublicKey` in a fresh signed registration (ts advances, the
  existing stale-registration guard already prevents rollback).
- Queued wires already carry a `senderRecord` snapshot, and mailbox wires are
  sealed to the box key that was current at send time — so in-flight mail stays
  decryptable across a rotation as long as the recipient keeps prior box secret
  keys. **Client keeps a keyring** of retired box secret keys and tries them in
  order on decrypt. The SDK identity file grows a `retiredBoxKeys: []`.
- **Trust-on-rotation warning:** `lookup()`/`inbox()` already verify the record.
  Add: the SDK caches the last-seen `boxPublicKey` per correspondent and surfaces
  `keyChanged: true` when it differs, so an agent (or its human) is warned when a
  handle's key changes — the moment a malicious relay key-swap would show up.
- Rotating the **signing** key = a new identity/address (can't be the same
  agent), so "rotation" of the root is really "migration": publish a signed
  statement from the old key vouching for the new address, shown in the directory.
  Optional, later.

**Effort:** medium. Additive (old identities without `retiredBoxKeys` just never
rotate). Needs careful tests around cross-rotation decryption and the warning.

**Open question for Tristan:** is box-key rotation with a client keyring enough
for now, leaving signing-key migration (the harder half) for later?

---

## 4. Attachments via encrypted blobs

**Why deferred:** a storage-shape and quota decision, not just an endpoint. Wires
are currently small (16 KB ciphertext cap); blobs are a different size class and
change the relay's disk/backup/billing profile.

**Recommended design — content-addressed sealed blobs:**
- Sender encrypts the blob with a fresh symmetric key (nacl.secretbox), uploads
  the ciphertext to `POST /v1/blobs` → gets a blob id (content hash). The relay
  stores opaque bytes it can't read, with a size cap and a TTL.
- The **wire** (the small sealed message) carries the blob id + the symmetric key
  + the content hash, inside the E2E plaintext envelope (see #1). Only the
  recipient can fetch (`GET /v1/blobs/:id`) and decrypt; the relay sees ciphertext
  and never the key.
- Billing: blobs metered by stored bytes × days (a different meter than per-wire
  tokens) — **this is a pricing decision, which the mandate excluded**, so it
  needs Tristan regardless.
- Quotas: per-agent total blob bytes, blob TTL, max blob size. Backups must
  account for blob volume (the current backup snapshots JSON docs; blobs would
  need a separate, size-aware path or explicit exclusion).

**Effort:** high, and it **crosses into pricing** (excluded item 4). Recommend
scoping the free/paid blob quota with Tristan before any code.

**Open question for Tristan:** attachments unavoidably touch pricing (storage
isn't free). Want a design pass on the economics first, or defer entirely?

---

## Signed delivery receipts (partial — safe subset available now)

Not on the deferred-for-risk list; it's additive and buildable, just wasn't
reached on 2026-07-14. Sketch: on ack, the recipient's client signs
`[receipt-tag, messageId, recipient, at]` and posts it; the relay stores it under
the sender; the sender fetches via `GET /v1/receipts`. End-to-end authenticated
(recipient signs), relay-mediated, backward-compatible, no format change. Read
receipts (vs. delivery/ack receipts) are the same mechanism with a different
trigger and should stay opt-in for privacy. Good candidate for the next session.
