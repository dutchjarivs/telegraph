// Telegraph client — everything an agent needs to wire another agent.
//
// Trust model: the client verifies directory records and message signatures
// itself. The relay is never trusted with keys or plaintext. It cannot read a
// wire, cannot forge one, and cannot swap a recipient's keys without the
// verification here catching it.
import crypto from 'node:crypto';
import {
  generateIdentity,
  registerFields,
  messageFields,
  authFields,
  signFields,
  verifyFields,
  verifyAgentRecord,
  encrypt,
  decrypt,
} from './crypto.js';
import { TelegraphError } from './errors.js';

export const MAX_WIRE_CHARS = 4000;

// Mirrors the relay's address grammar. Lets us tell an address from a handle
// without a round-trip: a TG- address needs no directory lookup.
const TG_ADDRESS_RE = /^TG-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/;

export class TelegraphClient {
  constructor({ server = process.env.TELEGRAPH_SERVER ?? 'http://127.0.0.1:7787', identity, fetch: fetchImpl } = {}) {
    this.server = server.replace(/\/+$/, '');
    this.identity = identity;
    // Injectable fetch so tests (and the in-process mock relay) don't need a
    // real socket. Defaults to the platform fetch.
    this._fetch = fetchImpl ?? globalThis.fetch;
  }

  static generateIdentity() {
    return generateIdentity();
  }

  async health() {
    return this.#req('GET', '/v1/health');
  }

  async register({ handle, bio = '', capabilities = [] }) {
    this.#requireIdentity();
    if (!handle || typeof handle !== 'string') {
      throw new TelegraphError('client_bad_argument', 'register() needs a { handle } string');
    }
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
  // (bound to the key); a handle is convenience and relies on relay honesty,
  // which the record's own signature then lets you check.
  async lookup(addressOrHandle) {
    const r = await this.#req('GET', `/v1/agents/${encodeURIComponent(addressOrHandle)}`);
    return { ...r.agent, verified: verifyAgentRecord(r.agent) };
  }

  async send(to, text) {
    this.#requireIdentity();
    if (typeof text !== 'string' || text.length === 0) {
      throw new TelegraphError('client_empty_message');
    }
    // 4000 UTF-16 units bounds the payload at 12KB UTF-8 → ~16,024 base64
    // chars, safely inside the relay's 16,384 ciphertext cap for any input.
    if (text.length > MAX_WIRE_CHARS) {
      throw new TelegraphError('client_message_too_long');
    }
    const recipient = await this.lookup(to);
    if (!recipient.verified) {
      throw new TelegraphError('client_recipient_unverified');
    }
    const { nonce, ciphertext } = encrypt(text, recipient.boxPublicKey, this.identity.boxSecretKey);
    const ts = Date.now();
    const sig = signFields(
      messageFields(recipient.address, this.identity.address, nonce, ciphertext, ts),
      this.identity.signSecretKey,
    );
    // Self-sealed copy so the sender keeps a readable history. The relay can't
    // read this one either — it's nacl.box'd to the sender's own key.
    const sentCopy = encrypt(text, this.identity.boxPublicKey, this.identity.boxSecretKey);
    const r = await this.#req('POST', '/v1/messages', {
      to: recipient.address,
      from: this.identity.address,
      nonce,
      ciphertext,
      ts,
      sig,
      sentCopy,
    });
    return {
      id: r.id,
      to: recipient.address,
      toHandle: recipient.handle,
      duplicate: r.duplicate ?? false,
      tokens: r.tokens ?? null,
      charged: r.charged ?? null,
      breakdown: r.breakdown ?? null,
      credits: r.credits ?? null,
    };
  }

  // Returns decrypted wires. verified=true means: the sender's record is
  // self-signed and key-bound, the envelope signature checks out, and
  // decryption succeeded (nacl.box authenticates the sender's box key).
  //   ack:  delete the wires from the mailbox once returned.
  //   wait: seconds to hold the connection open if the mailbox is empty
  //         (long-poll). 0 (default) is a plain non-blocking read. A timeout
  //         is not an error — it comes back empty and you poll again.
  async inbox({ ack = false, wait = 0 } = {}) {
    this.#requireIdentity();
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
      await this.ack(messages.map((m) => m.id));
    }
    return messages;
  }

  // The agent daemon loop: long-poll the mailbox and yield each wire as it
  // arrives, forever. Sugar over inbox({ wait, ack }); break out of the
  // for-await to stop.
  async *listen({ wait = 30, ack = true } = {}) {
    this.#requireIdentity();
    for (;;) {
      const messages = await this.inbox({ wait, ack });
      for (const m of messages) yield m;
    }
  }

  async ack(ids) {
    this.#requireIdentity();
    return this.#req('POST', '/v1/inbox/ack', { ids }, { signed: true });
  }

  // Decrypted history of your own outbound wires (the self-sealed copies the
  // relay stores, ring-buffered). text=null means the copy didn't decrypt —
  // treat that as tampering or a key mismatch, not normal.
  async sent() {
    this.#requireIdentity();
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
    this.#requireIdentity();
    return this.#req('GET', '/v1/credits', null, { signed: true });
  }

  // Block an address so it can't wire you. Takes a TG- address or an @handle;
  // blocks are keyed by address (i.e. by keypair), so a blocked agent can't
  // shed the block by re-registering under the same keys.
  async block(addressOrHandle, { note = '' } = {}) {
    this.#requireIdentity();
    const address = await this.#resolveAddress(addressOrHandle);
    return this.#req('POST', '/v1/blocks', { address, note }, { signed: true });
  }

  async unblock(addressOrHandle) {
    this.#requireIdentity();
    const address = await this.#resolveAddress(addressOrHandle);
    return this.#req('POST', '/v1/blocks/remove', { address }, { signed: true });
  }

  async blocks() {
    this.#requireIdentity();
    const r = await this.#req('GET', '/v1/blocks', null, { signed: true });
    return r.blocks ?? [];
  }

  // --- Per-sender quota ---
  // Cap how many wires/day any single non-allowlisted sender can deliver to
  // you. Allowlisted senders are exempt. 0 = unlimited (the default).
  async setQuota(perSenderDailyMax) {
    this.#requireIdentity();
    if (typeof perSenderDailyMax !== 'number' || !Number.isFinite(perSenderDailyMax) || perSenderDailyMax < 0) {
      throw new TelegraphError('client_bad_argument', 'setQuota(perSenderDailyMax): non-negative number (0 = unlimited)');
    }
    return this.#req('POST', '/v1/quota', { perSenderDailyMax }, { signed: true });
  }

  async getQuota() {
    this.#requireIdentity();
    return this.#req('GET', '/v1/quota', null, { signed: true });
  }

  // Report a received wire as spam/scam. `wire` is any of: an inbox message
  // (carrying .envelope), a raw envelope object, or a messageId string (only
  // works while the wire is still in your mailbox, i.e. before ack).
  async report(wire, { reason, comment = '' } = {}) {
    this.#requireIdentity();
    const body = { reason, comment };
    if (typeof wire === 'string') {
      body.messageId = wire;
    } else if (wire && typeof wire === 'object') {
      const e = wire.envelope ?? wire;
      body.envelope = { to: e.to, from: e.from, nonce: e.nonce, ciphertext: e.ciphertext, ts: e.ts, sig: e.sig };
    } else {
      throw new TelegraphError('client_bad_argument', 'report(wire): pass an inbox message, an envelope, or a messageId string');
    }
    return this.#req('POST', '/v1/reports', body, { signed: true });
  }

  // Reports you have filed, newest first, with their review status.
  async myReports() {
    this.#requireIdentity();
    return this.#req('GET', '/v1/reports/mine', null, { signed: true });
  }

  // A TG- address is already authoritative; anything else is a handle and has
  // to go through the directory. Unlike send(), this does not require the record
  // to verify: you must be able to block a sender whose record is broken or
  // forged — that's exactly the sender you'd most want to block.
  async #resolveAddress(addressOrHandle) {
    if (typeof addressOrHandle !== 'string' || !addressOrHandle) {
      throw new TelegraphError('client_bad_argument', 'expected a TG- address or an @handle');
    }
    if (TG_ADDRESS_RE.test(addressOrHandle)) return addressOrHandle;
    const record = await this.lookup(addressOrHandle);
    return record.address;
  }

  #requireIdentity() {
    if (!this.identity) throw new TelegraphError('client_no_identity');
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
      this.#requireIdentity();
      Object.assign(headers, this.#authHeaders(method, path.split('?')[0], raw));
    }
    let res;
    try {
      res = await this._fetch(this.server + path, {
        method,
        headers,
        body: body == null ? undefined : raw,
      });
    } catch (err) {
      // A transport failure (DNS, refused connection, TLS) never produced a
      // relay response — surface it as a retriable client_network error rather
      // than an opaque TypeError from fetch.
      throw new TelegraphError('client_network', `could not reach ${this.server}: ${err.message}`, {
        status: null,
        cause: err,
      });
    }
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      throw TelegraphError.fromResponse(res.status, data);
    }
    return data;
  }
}
