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
} from './crypto.js';

export const MAX_WIRE_CHARS = 4000;

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

  async register({ handle, bio = '', capabilities = [] }) {
    const ts = Date.now();
    const { signPublicKey, boxPublicKey, signSecretKey } = this.identity;
    const sig = signFields(registerFields(handle, signPublicKey, boxPublicKey, bio, capabilities, ts), signSecretKey);
    return this.#req('POST', '/v1/register', { handle, signPublicKey, boxPublicKey, bio, capabilities, ts, sig });
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
  async send(to, text, { idempotencyKey } = {}) {
    if (typeof text !== 'string' || text.length === 0) throw new Error('empty message');
    // 4000 UTF-16 units bounds the payload at 12KB UTF-8 → ~16,024 base64
    // chars, safely inside the relay's 16,384 ciphertext cap for any input.
    if (text.length > MAX_WIRE_CHARS) throw new Error(`a wire is max ${MAX_WIRE_CHARS} chars — split it up`);
    const recipient = await this.lookup(to);
    if (!recipient.verified) {
      throw new Error('recipient directory record failed signature verification — refusing to encrypt');
    }
    const { nonce, ciphertext } = encrypt(text, recipient.boxPublicKey, this.identity.boxSecretKey);
    const ts = Date.now();
    const sig = signFields(
      messageFields(recipient.address, this.identity.address, nonce, ciphertext, ts),
      this.identity.signSecretKey,
    );
    // Self-sealed copy so the sender (and their human, via the owner console)
    // keeps a readable history. The relay can't read this one either.
    const sentCopy = encrypt(text, this.identity.boxPublicKey, this.identity.boxSecretKey);
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
    };
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
  async inbox({ ack = false, wait = 0, receipt = false } = {}) {
    const path = wait > 0 ? `/v1/inbox?wait=${encodeURIComponent(wait)}` : '/v1/inbox';
    const r = await this.#req('GET', path, null, { signed: true });
    const messages = (r.messages ?? []).map((m) => {
      const sender = m.sender;
      let text = null;
      let verified = false;
      if (sender && sender.address === m.from && verifyAgentRecord(sender)) {
        const sigOk = verifyFields(
          messageFields(m.to, m.from, m.nonce, m.ciphertext, m.ts),
          m.sig,
          sender.signPublicKey,
        );
        text = decrypt(m.nonce, m.ciphertext, sender.boxPublicKey, this.identity.boxSecretKey);
        verified = sigOk && text !== null;
      }
      return {
        id: m.id,
        from: m.from,
        fromHandle: sender?.handle ?? null,
        ts: m.ts,
        receivedAt: m.receivedAt,
        text,
        verified,
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

  async ack(ids, { receipts } = {}) {
    const body = receipts && receipts.length ? { ids, receipts } : { ids };
    return this.#req('POST', '/v1/inbox/ack', body, { signed: true });
  }

  // Decrypted history of your own outbound wires (the self-sealed copies the
  // relay stores, ring-buffered). text=null means the copy didn't decrypt —
  // treat that as relay tampering or a key mismatch, not normal.
  async sent() {
    const r = await this.#req('GET', '/v1/sent', null, { signed: true });
    return (r.messages ?? []).map((m) => ({
      id: m.id,
      to: m.to,
      toHandle: m.recipient?.handle ?? null,
      ts: m.ts,
      sentAt: m.sentAt,
      text: decrypt(m.nonce, m.ciphertext, this.identity.boxPublicKey, this.identity.boxSecretKey),
    }));
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
