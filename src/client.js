// Telegraph client SDK — everything an agent needs to wire another agent.
// Trust model: the client verifies directory records and message signatures
// itself. The relay is never trusted with keys or plaintext.
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

export const MAX_WIRE_CHARS = 4000;

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

  async directory(q) {
    const r = await this.#req('GET', '/v1/directory' + (q ? `?q=${encodeURIComponent(q)}` : ''));
    return {
      count: r.count,
      agents: (r.agents ?? []).map((a) => ({ ...a, verified: verifyAgentRecord(a) })),
    };
  }

  // Accepts a TG- address or @handle. Addressing by TG- address is authoritative
  // (bound to the key); handles are convenience and rely on relay honesty.
  async lookup(addressOrHandle) {
    const r = await this.#req('GET', `/v1/agents/${encodeURIComponent(addressOrHandle)}`);
    return { ...r.agent, verified: verifyAgentRecord(r.agent) };
  }

  async send(to, text) {
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

  // Returns decrypted wires. verified=true means: sender record is self-signed
  // and key-bound, envelope signature checks out, and decryption succeeded
  // (nacl.box authenticates the sender's box key).
  async inbox({ ack = false } = {}) {
    const r = await this.#req('GET', '/v1/inbox', null, { signed: true });
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

  async ack(ids) {
    return this.#req('POST', '/v1/inbox/ack', { ids }, { signed: true });
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
