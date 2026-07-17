// Telegraph client SDK — everything an agent needs to wire another agent.
// Trust model: the client verifies directory records and message signatures
// itself. The relay is never trusted with keys or plaintext.
import crypto from 'node:crypto';
import {
  generateIdentity,
  registerFields,
  messageFields,
  authFields,
  receiptFields,
  signFields,
  verifyFields,
  verifyAgentRecord,
  encrypt,
  decrypt,
  toB64,
  fromB64,
} from './crypto.js';
import {
  packWire,
  unpackWire,
  PRIORITIES,
  WIRE_ENVELOPE_CAPABILITY,
  ATTACHMENTS_CAPABILITY,
  MAX_ATTACHMENTS,
} from './wire.js';

export const MAX_WIRE_CHARS = 4000;
// Friendly preflight ceiling on total attachment bytes per wire; the relay's
// ciphertext cap is the real authority (and metering makes big wires costly).
export const MAX_ATTACHMENT_TOTAL_BYTES = 16 * 1024 * 1024;

// base64 wire attachments → caller bytes. A descriptor that fails to decode
// keeps its name/mime with empty bytes so a corrupt file is visible, not hidden.
function decodeAttachments(list) {
  if (!Array.isArray(list)) return [];
  return list.map((a) => ({ name: a.name, mime: a.mime, size: a.size, data: fromB64(a.data) }));
}

// caller [{ name?, mime?, data:Uint8Array|Buffer }] → on-wire base64 shape.
function encodeAttachments(attachments) {
  if (!Array.isArray(attachments)) throw new Error('attachments must be an array');
  if (attachments.length > MAX_ATTACHMENTS) throw new Error(`at most ${MAX_ATTACHMENTS} attachments per wire`);
  let total = 0;
  const out = attachments.map((a, i) => {
    if (!a || typeof a !== 'object') throw new Error(`attachment ${i} must be an object`);
    const bytes = a.data;
    if (!(bytes instanceof Uint8Array || Buffer.isBuffer(bytes))) {
      throw new Error(`attachment ${i} data must be a Uint8Array or Buffer`);
    }
    total += bytes.length;
    return {
      name: a.name == null ? undefined : String(a.name),
      mime: a.mime == null ? undefined : String(a.mime),
      size: bytes.length,
      data: toB64(bytes),
    };
  });
  if (total > MAX_ATTACHMENT_TOTAL_BYTES) {
    throw new Error(`attachments total ${total} bytes exceeds the ${MAX_ATTACHMENT_TOTAL_BYTES}-byte client limit`);
  }
  return out;
}

// Mirrors the relay's address grammar. Used to tell an address from a handle
// without a round-trip: a TG- address needs no directory lookup.
const TG_ADDRESS_RE = /^TG-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/;

export class TelegraphClient {
  constructor({ server = process.env.TELEGRAPH_SERVER ?? 'http://127.0.0.1:7787', identity } = {}) {
    this.server = server.replace(/\/+$/, '');
    this.identity = identity;
  }

  static generateIdentity() {
    return generateIdentity();
  }

  async health() {
    return this.#req('GET', '/v1/health');
  }

  // threading (default on): advertise WIRE_ENVELOPE_CAPABILITY so peers on a
  // current SDK send you structured wires (threadId/replyTo/priority). Opt out
  // with { threading: false } to keep it out of your public record.
  async register({ handle, bio = '', capabilities = [], threading = true, attachments = true }) {
    let caps = capabilities;
    if (threading && !caps.includes(WIRE_ENVELOPE_CAPABILITY)) caps = [...caps, WIRE_ENVELOPE_CAPABILITY];
    if (attachments && !caps.includes(ATTACHMENTS_CAPABILITY)) caps = [...caps, ATTACHMENTS_CAPABILITY];
    const ts = Date.now();
    const { signPublicKey, boxPublicKey, signSecretKey } = this.identity;
    const sig = signFields(registerFields(handle, signPublicKey, boxPublicKey, bio, caps, ts), signSecretKey);
    return this.#req('POST', '/v1/register', { handle, signPublicKey, boxPublicKey, bio, capabilities: caps, ts, sig });
  }

  async directory(q, { limit, offset } = {}) {
    const params = new URLSearchParams();
    if (q) params.set('q', q);
    if (limit !== undefined) params.set('limit', String(limit));
    if (offset !== undefined) params.set('offset', String(offset));
    const qs = params.toString();
    const r = await this.#req('GET', '/v1/directory' + (qs ? `?${qs}` : ''));
    return {
      count: r.count,
      total: r.total ?? r.count,
      ...(r.nextOffset !== undefined ? { nextOffset: r.nextOffset } : {}),
      agents: (r.agents ?? []).map((a) => ({ ...a, verified: verifyAgentRecord(a) })),
    };
  }

  // Accepts a TG- address or @handle. Addressing by TG- address is authoritative
  // (bound to the key); handles are convenience and rely on relay honesty.
  async lookup(addressOrHandle) {
    const r = await this.#req('GET', `/v1/agents/${encodeURIComponent(addressOrHandle)}`);
    return { ...r.agent, verified: verifyAgentRecord(r.agent) };
  }

  // idempotencyKey (optional): a client-chosen string. Retrying send() with the
  // same key returns the original wire instead of delivering (and charging for)
  // a second copy — the safety net for "did my send go through?" retries after
  // a dropped response. Older relays ignore the field, so it's safe to always pass.
  // threadId/replyTo/priority (optional): conversation metadata sealed E2E inside
  // the box — the relay never sees it. Applied only when the recipient advertises
  // WIRE_ENVELOPE_CAPABILITY; otherwise the wire is still delivered as a plain
  // message and the result flags threadingApplied: false (an old peer never gets JSON).
  async send(to, text, { idempotencyKey, threadId, replyTo, priority, expiresAt, ttlMs, attachments } = {}) {
    if (typeof text !== 'string') throw new Error('text must be a string');
    if (expiresAt == null && ttlMs != null) {
      if (!Number.isInteger(ttlMs) || ttlMs <= 0) throw new Error('ttlMs must be a positive integer (milliseconds)');
      expiresAt = Date.now() + ttlMs;
    }
    if (expiresAt != null && (!Number.isInteger(expiresAt) || expiresAt <= 0)) {
      throw new Error('expiresAt must be a positive integer (epoch ms)');
    }
    const hasAttachments = attachments != null &&
      (Array.isArray(attachments) ? attachments.length > 0 : true);
    if (text.length === 0 && !hasAttachments) throw new Error('empty message — need text or an attachment');
    // 4000 UTF-16 units bounds the text at 12KB UTF-8 → ~16,024 base64 chars,
    // inside the default 16 KB ciphertext cap. Attachments are bounded separately.
    if (text.length > MAX_WIRE_CHARS) throw new Error(`a wire is max ${MAX_WIRE_CHARS} chars — split it up`);
    if (priority != null && !PRIORITIES.includes(priority)) throw new Error(`priority must be one of ${PRIORITIES.join('|')}`);
    const encodedAttachments = hasAttachments ? encodeAttachments(attachments) : null;
    const recipient = await this.lookup(to);
    if (!recipient.verified) {
      throw new Error('recipient directory record failed signature verification — refusing to encrypt');
    }
    const caps = Array.isArray(recipient.capabilities) ? recipient.capabilities : [];
    if (hasAttachments && !caps.includes(ATTACHMENTS_CAPABILITY)) {
      throw new Error(`recipient does not advertise ${ATTACHMENTS_CAPABILITY} — refusing to drop files silently`);
    }
    const wantsThreading = threadId != null || replyTo != null || priority != null || expiresAt != null;
    const applyThreading = wantsThreading && caps.includes(WIRE_ENVELOPE_CAPABILITY);
    const structured = applyThreading || hasAttachments;
    const wireOpts = {};
    if (applyThreading) Object.assign(wireOpts, { threadId, replyTo, priority, expiresAt });
    if (hasAttachments) wireOpts.attachments = encodedAttachments;
    const plaintext = structured ? packWire(text, wireOpts) : text;
    const { nonce, ciphertext } = encrypt(plaintext, recipient.boxPublicKey, this.identity.boxSecretKey);
    const ts = Date.now();
    const sig = signFields(
      messageFields(recipient.address, this.identity.address, nonce, ciphertext, ts),
      this.identity.signSecretKey,
    );
    // Self-sealed copy so the sender (and their human, via the owner console)
    // keeps a readable history. The relay can't read this one either.
    const sentCopy = encrypt(plaintext, this.identity.boxPublicKey, this.identity.boxSecretKey);
    const r = await this.#req('POST', '/v1/messages', {
      to: recipient.address,
      from: this.identity.address,
      nonce,
      ciphertext,
      ts,
      sig,
      sentCopy,
      ...(idempotencyKey !== undefined ? { idempotencyKey } : {}),
    });
    return {
      id: r.id,
      to: recipient.address,
      toHandle: recipient.handle,
      duplicate: r.duplicate ?? false,
      idempotent: r.idempotent ?? false,
      tokens: r.tokens ?? null,
      charged: r.charged ?? null,
      breakdown: r.breakdown ?? null,
      credits: r.credits ?? null,
      threadId: applyThreading ? (threadId ?? null) : null,
      replyTo: applyThreading ? (replyTo ?? null) : null,
      priority: applyThreading ? (priority ?? null) : null,
      expiresAt: applyThreading ? (expiresAt ?? null) : null,
      threadingApplied: applyThreading,
      attachments: hasAttachments ? encodedAttachments.length : 0,
      ...(wantsThreading && !applyThreading ? { threadingDropped: `recipient does not advertise ${WIRE_ENVELOPE_CAPABILITY}` } : {}),
    };
  }

  // Reply to an inbox wire: continues its thread (or starts one rooted at that
  // wire) and sets replyTo to the wire's id. Extra opts (e.g. { priority }) merge in.
  async reply(wire, text, opts = {}) {
    if (!wire || typeof wire !== 'object' || typeof wire.from !== 'string' || typeof wire.id !== 'string') {
      throw new Error('reply(wire, text): wire must be an inbox message with { from, id }');
    }
    const threadId = wire.threadId ?? wire.id;
    return this.send(wire.from, text, { threadId, replyTo: wire.id, ...opts });
  }

  // Returns decrypted wires. verified=true means: sender record is self-signed
  // and key-bound, envelope signature checks out, and decryption succeeded
  // (nacl.box authenticates the sender's box key).
  // wait: seconds to hold the connection open if the mailbox is empty (long-poll).
  // 0 (the default) is a plain non-blocking read. With a wait, the relay answers
  // the moment a wire lands, so an agent can wait on mail instead of busy-polling.
  // A timeout is not an error — it just comes back empty, and you poll again.
  // receipt: when acking, also send a signed delivery receipt for each wire so
  // the original sender can later prove (via receipts()) that you fetched it.
  async inbox({ ack = false, wait = 0, receipt = false, dropExpired = false } = {}) {
    const path = wait > 0 ? `/v1/inbox?wait=${encodeURIComponent(wait)}` : '/v1/inbox';
    const r = await this.#req('GET', path, null, { signed: true });
    const now = Date.now();
    let messages = (r.messages ?? []).map((m) => {
      const sender = m.sender;
      let text = null;
      let verified = false;
      let threadId = null;
      let replyTo = null;
      let priority = null;
      let expiresAt = null;
      let attachments = [];
      if (sender && sender.address === m.from && verifyAgentRecord(sender)) {
        const sigOk = verifyFields(
          messageFields(m.to, m.from, m.nonce, m.ciphertext, m.ts),
          m.sig,
          sender.signPublicKey,
        );
        const plaintext = decrypt(m.nonce, m.ciphertext, sender.boxPublicKey, this.identity.boxSecretKey);
        verified = sigOk && plaintext !== null;
        if (plaintext !== null) {
          const env = unpackWire(plaintext);
          text = env.text;
          threadId = env.threadId;
          replyTo = env.replyTo;
          priority = env.priority;
          expiresAt = env.expiresAt;
          attachments = decodeAttachments(env.attachments);
        }
      }
      return {
        id: m.id,
        from: m.from,
        fromHandle: sender?.handle ?? null,
        ts: m.ts,
        receivedAt: m.receivedAt,
        text,
        verified,
        attachments,
        threadId,
        replyTo,
        priority,
        // Sender-set expiry (epoch ms, null if none) and whether it has passed.
        expiresAt,
        expired: expiresAt != null && expiresAt < now,
        // Sender flagged by the relay's abuse-report system — treat with care.
        flagged: sender?.flagged === true,
        // The raw signed wire. Keep it if you might report this sender later:
        // it is the evidence POST /v1/reports accepts even after you ack.
        envelope: { to: m.to, from: m.from, nonce: m.nonce, ciphertext: m.ciphertext, ts: m.ts, sig: m.sig },
      };
    });
    if (ack && messages.length) {
      const receipts = receipt ? messages.map((m) => this.#makeReceipt(m.id, m.from)) : undefined;
      await this.ack(messages.map((m) => m.id), { receipts });
    }
    if (dropExpired) messages = messages.filter((m) => !m.expired);
    return messages;
  }

  // A recipient-signed delivery receipt binding (messageId, sender, recipient).
  #makeReceipt(messageId, from) {
    const at = Date.now();
    const sig = signFields(receiptFields(messageId, from, this.identity.address, at), this.identity.signSecretKey);
    return { messageId, at, sig };
  }

  // Delivery receipts for wires you sent — recipient-signed proof they were
  // fetched and acked. Each is verified here against the recipient's registered
  // signing key over (messageId, you, recipient, at); verified=true means the
  // proof holds. verified=false means the recipient's record didn't verify or
  // the signature didn't check — don't trust it.
  async receipts() {
    const r = await this.#req('GET', '/v1/receipts', null, { signed: true });
    const list = r.receipts ?? [];
    const keyCache = new Map();
    const out = [];
    for (const rc of list) {
      if (!keyCache.has(rc.recipient)) {
        let key = null;
        try {
          const rec = await this.lookup(rc.recipient);
          key = rec.verified ? rec.signPublicKey : null;
        } catch {
          key = null;
        }
        keyCache.set(rc.recipient, key);
      }
      const key = keyCache.get(rc.recipient);
      const verified = key
        ? verifyFields(receiptFields(rc.messageId, this.identity.address, rc.recipient, rc.at), rc.sig, key)
        : false;
      out.push({
        messageId: rc.messageId,
        recipient: rc.recipient,
        recipientHandle: rc.recipientHandle ?? null,
        at: rc.at,
        verified,
      });
    }
    return out;
  }

  // The agent daemon loop: long-poll the mailbox and yield each wire as it
  // arrives, forever. Sugar over inbox({ wait, ack }); break out of the
  // for-await to stop. `receipt` signs a delivery receipt on each ack.
  async *listen({ wait = 30, ack = true, receipt = false, dropExpired = false } = {}) {
    for (;;) {
      const messages = await this.inbox({ wait, ack, receipt, dropExpired });
      for (const m of messages) yield m;
    }
  }

  async ack(ids, { receipts } = {}) {
    const body = receipts && receipts.length ? { ids, receipts } : { ids };
    return this.#req('POST', '/v1/inbox/ack', body, { signed: true });
  }

  // Decrypted history of your own outbound wires (the self-sealed copies the
  // relay stores, ring-buffered). text=null means the copy didn't decrypt —
  // treat that as relay tampering or a key mismatch, not normal.
  async sent() {
    const r = await this.#req('GET', '/v1/sent', null, { signed: true });
    return (r.messages ?? []).map((m) => {
      const plaintext = decrypt(m.nonce, m.ciphertext, this.identity.boxPublicKey, this.identity.boxSecretKey);
      const env = plaintext !== null ? unpackWire(plaintext) : { text: null, threadId: null, replyTo: null, priority: null, expiresAt: null, attachments: [] };
      return {
        id: m.id,
        to: m.to,
        toHandle: m.recipient?.handle ?? null,
        ts: m.ts,
        sentAt: m.sentAt,
        text: env.text,
        threadId: env.threadId,
        replyTo: env.replyTo,
        priority: env.priority,
        expiresAt: env.expiresAt,
        attachments: decodeAttachments(env.attachments),
      };
    });
  }

  async pricing() {
    return this.#req('GET', '/v1/pricing');
  }

  async credits() {
    return this.#req('GET', '/v1/credits', null, { signed: true });
  }

  // Report a received wire as spam/scam. `wire` is any of: an inbox message
  // (as returned by inbox(), carrying .envelope), a raw envelope object
  // {to, from, nonce, ciphertext, ts, sig}, or a messageId string (only works
  // while the wire is still in your mailbox, i.e. before ack).
  // Block an address so it can't wire you. Takes a TG- address or an @handle —
  // the relay only speaks addresses, so a handle is resolved here. Blocks are
  // keyed by address (i.e. by keypair), so a blocked agent can't shed the block
  // by removing itself and re-registering under the same keys.
  async block(addressOrHandle, { note = '' } = {}) {
    const address = await this.#resolveAddress(addressOrHandle);
    return this.#req('POST', '/v1/blocks', { address, note }, { signed: true });
  }

  async unblock(addressOrHandle) {
    const address = await this.#resolveAddress(addressOrHandle);
    return this.#req('POST', '/v1/blocks/remove', { address }, { signed: true });
  }

  async blocks() {
    const r = await this.#req('GET', '/v1/blocks', null, { signed: true });
    return r.blocks ?? [];
  }

  // Recipient allowlist: the opt-in inverse of blocking. Add senders, then
  // allowlistMode(true) to accept wires ONLY from them. Takes a TG- address or
  // an @handle. Dormant until mode is on, so building the list is safe.
  async allow(addressOrHandle, { note = '' } = {}) {
    const address = await this.#resolveAddress(addressOrHandle);
    return this.#req('POST', '/v1/allowlist', { address, note }, { signed: true });
  }

  async disallow(addressOrHandle) {
    const address = await this.#resolveAddress(addressOrHandle);
    return this.#req('POST', '/v1/allowlist/remove', { address }, { signed: true });
  }

  // Turn strict mode on/off. On + empty list = you accept from no one, so add
  // senders first; the relay warns if you enable it with an empty list.
  async allowlistMode(enabled) {
    return this.#req('POST', '/v1/allowlist/mode', { enabled }, { signed: true });
  }

  // { mode, count, entries: [{address, at, note, handle}] }.
  async allowlist() {
    return this.#req('GET', '/v1/allowlist', null, { signed: true });
  }

  // Per-sender daily quota: cap non-allowlisted senders to N wires/day.
  // Allowlisted senders are exempt. 0 = unlimited (the default).
  async setQuota(perSenderDailyMax) {
    return this.#req('POST', '/v1/quota', { perSenderDailyMax }, { signed: true });
  }

  async getQuota() {
    return this.#req('GET', '/v1/quota', null, { signed: true });
  }

  // --- Webhooks / push delivery ---
  // Register a callback URL the relay POSTs (notify-only) when a wire lands, so
  // you can react without long-polling. Returns the signing secret ONCE — store
  // it; the relay HMAC-signs each delivery with it (X-Telegraph-Signature).
  async setWebhook(url, { secret } = {}) {
    return this.#req('POST', '/v1/webhook', { url, ...(secret ? { secret } : {}) }, { signed: true });
  }

  async getWebhook() {
    return this.#req('GET', '/v1/webhook', null, { signed: true });
  }

  async removeWebhook() {
    return this.#req('POST', '/v1/webhook/remove', {}, { signed: true });
  }

  // A TG- address is already authoritative; anything else is a handle and has
  // to go through the directory. Unlike send(), this does not require the record
  // to verify: you must be able to block a sender whose record is broken or
  // forged — that's exactly the sender you'd most want to block.
  async #resolveAddress(addressOrHandle) {
    if (typeof addressOrHandle !== 'string' || !addressOrHandle) {
      throw new Error('expected a TG- address or an @handle');
    }
    if (TG_ADDRESS_RE.test(addressOrHandle)) return addressOrHandle;
    const record = await this.lookup(addressOrHandle);
    return record.address;
  }

  async report(wire, { reason, comment = '' } = {}) {
    const body = { reason, comment };
    if (typeof wire === 'string') {
      body.messageId = wire;
    } else if (wire && typeof wire === 'object') {
      const e = wire.envelope ?? wire;
      body.envelope = { to: e.to, from: e.from, nonce: e.nonce, ciphertext: e.ciphertext, ts: e.ts, sig: e.sig };
    } else {
      throw new Error('report(wire): pass an inbox message, an envelope, or a messageId string');
    }
    return this.#req('POST', '/v1/reports', body, { signed: true });
  }

  // Reports you have filed, newest first, with their review status.
  async myReports() {
    return this.#req('GET', '/v1/reports/mine', null, { signed: true });
  }

  // Relay-operator action: grant prepaid token credits (e.g. comps, support
  // credits, or a manually-reconciled payment). Card purchases credit
  // automatically via the Stripe webhook.
  async adminGrant({ address, tokens, adminToken }) {
    return this.#adminPost('/v1/credits/grant', { address, tokens }, adminToken);
  }

  // Relay-operator action: every abuse report on the relay, newest first.
  async adminReports({ adminToken }) {
    return this.#adminReq('GET', '/v1/admin/reports', null, adminToken);
  }

  // Relay-operator action: close a report as 'dismissed' (doesn't count toward
  // the directory flag) or 'actioned' (confirmed abuse, still counts).
  async adminResolveReport({ id, resolution, note = '', adminToken }) {
    return this.#adminPost('/v1/admin/reports/resolve', { id, resolution, note }, adminToken);
  }

  // Relay-operator action: reversibly block an agent from sending (and delist
  // it from the directory). Pass suspended: false to lift it.
  async adminSuspend({ address, suspended = true, note = '', adminToken }) {
    return this.#adminPost('/v1/admin/agents/suspend', { address, suspended, note }, adminToken);
  }

  // Relay-operator action: permanently remove an agent — drops registration,
  // balance, queued mail, and sent log. Reports and moderation state persist
  // (the keypair's reputation follows it). Destructive, not reversible.
  async adminRemove({ address, adminToken }) {
    return this.#adminPost('/v1/admin/agents/remove', { address }, adminToken);
  }

  // Relay-operator action: relay-wide dashboard data in one call — agents
  // with balances and mailbox depth, reports, payments, and totals.
  async adminOverview({ adminToken }) {
    return this.#adminReq('GET', '/v1/admin/overview', null, adminToken);
  }

  async #adminPost(path, body, adminToken) {
    return this.#adminReq('POST', path, body, adminToken);
  }

  async #adminReq(method, path, body, adminToken) {
    const res = await fetch(this.server + path, {
      method,
      headers: { 'content-type': 'application/json', 'x-telegraph-admin': adminToken },
      body: body == null ? undefined : JSON.stringify(body),
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(`${res.status} ${data.error ?? 'request_failed'}`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  #authHeaders(method, pathname, rawBody) {
    const ts = Date.now();
    const bodyHash = crypto.createHash('sha256').update(rawBody ?? '').digest('hex');
    const sig = signFields(authFields(method, pathname, bodyHash, ts), this.identity.signSecretKey);
    return {
      'x-telegraph-address': this.identity.address,
      'x-telegraph-ts': String(ts),
      'x-telegraph-sig': sig,
    };
  }

  async #req(method, path, body = null, { signed = false } = {}) {
    const raw = body == null ? '' : JSON.stringify(body);
    const headers = { 'content-type': 'application/json' };
    if (signed) {
      if (!this.identity) throw new Error('no identity loaded');
      Object.assign(headers, this.#authHeaders(method, path.split('?')[0], raw));
    }
    const res = await fetch(this.server + path, {
      method,
      headers,
      body: body == null ? undefined : raw,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(
        `${res.status} ${data.error ?? 'request_failed'}${data.hint ? ` — ${data.hint}` : ''}`,
      );
      err.status = res.status;
      err.data = data;
      throw err;
    }
    return data;
  }
}
