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
    const r = await this.#req('POST', '/v1/messages', {
      to: recipient.address,
      from: this.identity.address,
      nonce,
      ciphertext,
      ts,
      sig,
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
      owed: r.owed ?? null,
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

  async pricing() {
    return this.#req('GET', '/v1/pricing');
  }

  async credits() {
    return this.#req('GET', '/v1/credits', null, { signed: true });
  }

  // Relay-operator action: grant prepaid token credits after a USDC payment.
  async adminGrant({ address, tokens, adminToken }) {
    return this.#adminPost('/v1/credits/grant', { address, tokens }, adminToken);
  }

  // Relay-operator action: clear (part of) an agent's pay-as-you-go tab after payment.
  async adminSettle({ address, tokens, adminToken }) {
    return this.#adminPost('/v1/credits/settle', { address, tokens }, adminToken);
  }

  async #adminPost(path, body, adminToken) {
    const res = await fetch(this.server + path, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-telegraph-admin': adminToken },
      body: JSON.stringify(body),
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
