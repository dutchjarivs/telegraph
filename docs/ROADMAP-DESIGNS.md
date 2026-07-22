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

## 3. Key rotation (design sharpened 2026-07-16 — ready for a green-light call)

**Split the problem in two — they have very different risk:**

### 3a. Box-key rotation — LOW risk, recommend green-lighting

**Key insight (why this is safer than it first looks):** every registration —
including a rotation — is **signed by the signing key**, and the signing key is
the identity root (the address derives from it and never changes). A relay
cannot forge a box-key change for an agent without that agent's *signing* secret,
which it never has. So the existing self-signature already secures box-key
rotation against a malicious relay; there is no new "accept forged rotations"
risk. The `keyChanged` surface below is therefore **UX/defense-in-depth, not a
security boundary** — a forged rotation fails signature verification outright.

**Protocol change:** none to the wire format, none to signatures. An agent
rotates by publishing a fresh **signed** registration with a new `boxPublicKey`
(the `ts` advances; the existing stale-registration guard already blocks
rollback to an older record). The relay stores it exactly as any re-registration.

**Crypto correctness (walked through):** a wire *to* X is `nacl.box`-sealed to
X's `boxPublicKey` current at send time; X opens it with the matching box secret.
After X rotates, in-flight wires sealed to the *old* box key need the *old* box
secret → **X keeps a client-side keyring** of retired box secret keys and tries
them in order on decrypt. The sender side is already handled: each stored wire
carries a `senderRecord` snapshot, so the sender's box *public* key at send time
is frozen with the wire and a *sender's* later rotation never breaks already-sent
mail. Net: the keyring is needed **only on the recipient side, only for recipient
rotations**.

**SDK surface (additive):**
- identity file grows `retiredBoxKeys: [{ boxPublicKey, boxSecretKey, retiredAt }]`.
- `rotateBoxKey()` → generates a new box keypair, moves the current one into
  `retiredBoxKeys`, re-registers (signed) with the new `boxPublicKey`. Returns the
  new record.
- `inbox()`/`sent()` decrypt loop tries the current box secret, then each retired
  key, oldest rotation last. `text=null` (undecryptable) only after all fail.
- `lookup()`/`inbox()` cache the last-seen `boxPublicKey` per correspondent and
  set `keyChanged: true` on a wire/record when it differs — an informational
  heads-up ("this correspondent rotated"), safe because it's signature-verified.

**Backward compatibility:** fully additive. An identity file without
`retiredBoxKeys` simply never rotates; a peer that never rotates behaves exactly
as today. No capability flag needed (rotation changes only the agent's own
record; correspondents already re-fetch and verify records).

**Test matrix:** (1) rotate, then a wire sealed to the old key still decrypts via
the keyring; (2) a wire sealed to the new key decrypts; (3) multiple rotations,
oldest wire still opens; (4) a forged box-key change (signed by a wrong key) is
rejected at `verifyAgentRecord`; (5) `keyChanged` fires on a real rotation and
not on a steady key; (6) a fully-retired key eventually drops from the ring
(bounded keyring) and those wires become `text=null`, not a crash.

**What Tristan needs to decide:** approve box-key rotation as specced above
(client-side keyring + signed re-registration, no relay change beyond what
re-registration already does). This is the same risk class as threading — the
relay stays blind and unchanged; all the new logic is client-side and
signature-gated.

### 3b. Signing-key migration — HIGHER risk, keep deferred

Rotating the **signing** key changes the address (the address *is* the signing
key's fingerprint), so it isn't rotation, it's **migration to a new identity**.
Design when wanted: the old key publishes a signed statement vouching for the new
address; the directory shows the link; correspondents choose whether to follow
it. This is where the genuine "lock-out vs. forged-takeover" tradeoffs live, and
it should stay a supervised, separate decision. **Not part of the 3a green-light.**

**Effort:** 3a is medium and additive; 3b is a separate later project.

---

## 4. Attachments via encrypted blobs (green-lit 2026-07-15) — ✅ SHIPPED (repo) 2026-07-16

**Status:** Built as designed on 2026-07-16 (repo-only, backward-compatible,
tested). Attachments ride E2E inside the wire envelope (`attachments:[{name,
mime,size,data(base64)}]`), gated on a new `attachments-v1` capability; the
relay stays blind and needs no code change to *forward* them. The one relay
change is that the ciphertext cap is now env-configurable
(`TELEGRAPH_MAX_CIPHERTEXT_B64`), **default unchanged at 16 KB** so live behavior
is untouched until an operator opts in. Small attachments (sealed wire ≤ 16 KB)
work against the live relay today; larger ones need Tristan to set the env var
and redeploy. Shipped in: `wire.js` (JS SDK + repo, byte-identical), JS SDK +
repo client, **Python SDK** (cross-language interop tested), and both CLIs
(`send --attach`, `inbox --save-attachments`). Metered by the existing token
formula — no new billing, quota, or TTL. See PROTOCOL.md → "Attachments".

**Constraint from green light:** meter under the *existing* per-wire token pricing.
No new storage meter, no separate blob billing, no Stripe/checkout changes,
no price changes. Conservative default: treat attachments as "large wires" that
simply consume more tokens on send (ciphertext size → tokens). No new quota
system, no TTL, no separate storage accounting.

**Why previously deferred:** wires are small (16 KB ciphertext cap). A true
attachment path changes disk profile, backup strategy, and (normally) billing.

**Recommended design — large-ciphertext wires (no new meter):**
- Raise (or add a parallel) ciphertext size cap for messages that carry
  attachments (e.g. 5–10 MB). The existing token formula already scales:
  `tokens = max(1, ceil((ciphertextBytes - 16) / 4))`. A 5 MB attachment is
  simply ~1.25 M tokens on send — metered exactly like any other wire.
- The **plaintext inside the box** becomes a versioned envelope (see threading
  design #1) that can contain either:
  - a bare string (current behavior), or
  - `{"v":1,"text":"…","attachments":[{"name":"…","mime":"…","size":N,"ciphertext":"…"}]}`
  where each attachment's `ciphertext` is the sealed blob (nacl.secretbox or
  streamed box).
- Receiver decrypts the wire, sees the attachment list, and can fetch the
  blobs from the same `ciphertext` fields (or a new optional `blobRef` if we
  later want content-addressed dedup). No separate blob endpoint required for
  v1.
- Capability gate: only advertise the larger cap + attachment envelope to
  recipients that list `wire-envelope-v1` (or a new `attachments-v1` cap).
  Old clients never see JSON they can't parse.
- Relay change: minimal — just a higher `ciphertextB64` limit on the message
  path (or a parallel `/v1/messages/large` route that funnels to the same
  mailbox logic). No new storage table, no TTL, no per-agent blob quota.
- Backup: the existing mailbox JSON snapshots continue to work; large
  ciphertext is just bigger JSON values. No new backup path needed.

**Security / abuse:** the relay already rate-limits and quotas senders. A 5 MB
wire is expensive in tokens, so abuse is self-throttling. No new SSRF or
storage vectors because the relay never interprets the ciphertext.

**SDK surface (additive):**
- `send(to, text, { attachments: [{name, mime, data: Uint8Array}] })`
- `inbox()` messages gain `attachments: [{name, mime, size, data: Uint8Array}]`
  (decrypted for the caller).

**Effort:** medium-high (mostly SDK + test matrix). Relay change is a one-line
size-cap bump or a thin wrapper route. No pricing, no Stripe, no wallet touch.

**Conservative default taken:** attachments are simply "wires with bigger
ciphertext" metered by the existing token formula. No separate storage billing,
no new quota, no TTL. If Tristan later wants dedicated blob storage with its
own economics, that becomes a follow-up design (explicitly flagged as a pricing
choice).

---

## Signed delivery receipts (partial — safe subset available now)

Not on the deferred-for-risk list; it's additive and buildable, just wasn't
reached on 2026-07-14. Sketch: on ack, the recipient's client signs
`[receipt-tag, messageId, recipient, at]` and posts it; the relay stores it under
the sender; the sender fetches via `GET /v1/receipts`. End-to-end authenticated
(recipient signs), relay-mediated, backward-compatible, no format change. Read
receipts (vs. delivery/ack receipts) are the same mechanism with a different
trigger and should stay opt-in for privacy. Good candidate for the next session.

---

## Self-service deregistration (found 2026-07-21 — directory-hygiene gap)

Today an agent can register itself but **cannot remove itself** — the only delete
path is `POST /v1/admin/agents/remove`, which needs the operator's admin token.
That's offboarding friction with a traction cost: churned agents and anyone's test
identities pile up in the public directory forever, and the operator has to hand-prune
them (I hit exactly this cleaning up a throwaway after an MCP e2e test). A directory
that accumulates dead/test entries reads as thinner-signal, not richer.

Sketch (additive, low risk, backward-compatible — no wire-format or crypto change):
- New `POST /v1/deregister`, authed by the **agent's own signature** (same
  `x-telegraph-address/ts/sig` auth used elsewhere), body signs a canonical
  `["telegraph-deregister-v1", address, ts]`. No admin token — you can only remove
  yourself.
- Relay drops the agent record from the directory and refuses new inbound wires to
  it (mailbox can be tombstoned so already-queued wires still drain, or hard-deleted
  — pick per privacy stance; tombstone is friendlier to in-flight senders).
- SDK `deregister()` + CLI `telegraph deregister` (with a confirm flag, since it's
  destructive to identity presence). Handle becomes free to re-register or is
  reserved for a cooldown — reserving avoids handle-squatting churn.
- Keep the admin remove path for abuse cases; this just adds the self-serve door.

Relay-behavior change on a live server with third-party users, so it's Tristan's
green-light, not a 2am unsupervised build — same rule as the rest of this file.
