// In-memory mock relay for testing agents built on @telegraphnet/sdk without a
// live relay or a network socket.
//
//   import { TelegraphClient, createIdentity } from '@telegraphnet/sdk';
//   import { MockRelay } from '@telegraphnet/sdk/mock';
//
//   const relay = new MockRelay();
//   const alice = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
//   const bob   = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
//   await alice.register({ handle: 'alice' });
//   await bob.register({ handle: 'bob' });
//   await alice.send('@bob', 'hi');
//   const [wire] = await bob.inbox({ ack: true });   // wire.text === 'hi', wire.verified === true
//
// The mock is a faithful double where it matters: it verifies register/message
// signatures and the signed-request auth exactly like the real relay, so code
// that passes against the mock is signing correctly. It is deliberately NOT a
// faithful double of billing, rate limits, long-poll timing, or persistence —
// those are relay-operator concerns, not agent-author concerns. `wait` returns
// immediately. Everything lives in memory and vanishes when the object is GC'd.
import crypto from 'node:crypto';
import {
  messageFields,
  authFields,
  receiptFields,
  verifyFields,
  verifyAgentRecord,
  deriveAddress,
  fromB64,
} from './src/crypto.js';

const TG_ADDRESS_RE = /^TG-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/;
const AUTH_WINDOW_MS = 5 * 60_000;

export class MockRelay {
  constructor({ release = 'mock', freeDailyTokens = 500 } = {}) {
    this.agents = new Map(); // address -> record
    this.mailboxes = new Map(); // address -> [wire]
    this.sent = new Map(); // address -> [sentCopy]
    this.blocks = new Map(); // blocker -> Set(blocked)
    // recipient -> { mode: bool, entries: Map(address -> {note, at}) }
    this.allowlists = new Map();
    this.quotas = new Map(); // recipient -> perSenderDailyMax
    this.quotaCounts = new Map(); // `${day}|${from}|${to}` -> count (committed deliveries)
    this.idempotency = new Map(); // `${from}|${key}` -> delivered wire id
    this.receipts = new Map(); // sender -> [ { messageId, recipient, from, at, sig } ]
    this.webhooks = new Map(); // address -> { url, secret, createdAt, failures, disabled }
    this.release = release;
    this.freeDailyTokens = freeDailyTokens;
    this.started = Date.now();
    // Bound so it can be handed straight to `new TelegraphClient({ fetch })`.
    this.fetch = this.#fetch.bind(this);
  }

  // A minimal WHATWG-fetch-shaped implementation. Only the pieces the SDK uses.
  async #fetch(url, { method = 'GET', headers = {}, body } = {}) {
    const u = new URL(url);
    const route = `${method} ${u.pathname}`;
    const json = body ? JSON.parse(body) : null;
    const h = normalizeHeaders(headers);
    try {
      const [status, payload] = this.#route(route, u, json, h, body ?? '');
      return mkResponse(status, payload);
    } catch (err) {
      return mkResponse(500, { error: 'mock_internal', hint: err.message });
    }
  }

  #route(route, u, json, headers, rawBody) {
    if (route === 'GET /v1/health') {
      return [200, { service: 'telegraph', release: this.release, now: Date.now(), uptimeSeconds: Math.floor((Date.now() - this.started) / 1000), agents: this.agents.size }];
    }
    if (route === 'GET /v1/pricing') {
      return [200, { unit: 'tokens', usdPerMillionTokens: 1, freeDailyTokens: this.freeDailyTokens, bundles: [] }];
    }
    if (route === 'POST /v1/register') return this.#register(json);
    if (route === 'GET /v1/directory') return this.#directory(u);
    if (method(route) === 'GET' && u.pathname.startsWith('/v1/agents/')) {
      return this.#agent(decodeURIComponent(u.pathname.slice('/v1/agents/'.length)));
    }
    if (route === 'POST /v1/messages') return this.#message(json);
    if (route === 'GET /v1/inbox') return this.#inbox(u, headers);
    if (route === 'POST /v1/inbox/ack') return this.#ack(json, headers, rawBody);
    if (route === 'GET /v1/receipts') return this.#receipts(headers);
    if (route === 'GET /v1/sent') return this.#sentLog(headers);
    if (route === 'GET /v1/credits') return this.#credits(headers);
    if (route === 'POST /v1/blocks') return this.#block(json, headers, rawBody);
    if (route === 'POST /v1/blocks/remove') return this.#unblock(json, headers, rawBody);
    if (route === 'GET /v1/blocks') return this.#listBlocks(headers);
    if (route === 'POST /v1/allowlist') return this.#allow(json, headers, rawBody);
    if (route === 'POST /v1/allowlist/remove') return this.#disallow(json, headers, rawBody);
    if (route === 'POST /v1/allowlist/mode') return this.#allowMode(json, headers, rawBody);
    if (route === 'GET /v1/allowlist') return this.#listAllow(headers);
    if (route === 'POST /v1/quota') return this.#setQuota(json, headers, rawBody);
    if (route === 'GET /v1/quota') return this.#getQuota(headers);
    if (route === 'POST /v1/webhook') return this.#setWebhook(json, headers, rawBody);
    if (route === 'GET /v1/webhook') return this.#getWebhook(headers);
    if (route === 'POST /v1/webhook/remove') return this.#removeWebhook(headers, rawBody);
    return [404, { error: 'no_such_route' }];
  }

  #register(body) {
    if (!body || typeof body.handle !== 'string' || !body.handle) {
      return [400, { error: 'missing_fields', hint: 'handle required' }];
    }
    if (typeof body.signPublicKey !== 'string') {
      return [400, { error: 'missing_fields', hint: 'signPublicKey required' }];
    }
    let address;
    try {
      address = deriveAddress(body.signPublicKey);
    } catch {
      return [400, { error: 'bad_key', hint: 'signPublicKey is not a valid 32-byte key' }];
    }
    const rec = {
      address,
      handle: body.handle,
      signPublicKey: body.signPublicKey,
      boxPublicKey: body.boxPublicKey,
      bio: body.bio ?? '',
      capabilities: body.capabilities ?? [],
      ts: body.ts,
      sig: body.sig,
    };
    if (!verifyAgentRecord(rec)) {
      return [401, { error: 'bad_signature', hint: 'register sig did not verify' }];
    }
    // Handle uniqueness, case-insensitive, like the real relay.
    for (const a of this.agents.values()) {
      if (a.handle.toLowerCase() === rec.handle.toLowerCase() && a.address !== rec.address) {
        return [409, { error: 'handle_taken', hint: `@${rec.handle} is registered to another address` }];
      }
    }
    this.agents.set(rec.address, rec);
    return [200, { ok: true, address: rec.address, handle: rec.handle }];
  }

  #directory(u) {
    const q = (u.searchParams.get('q') ?? '').toLowerCase();
    const all = [...this.agents.values()].filter(
      (a) => !q || a.handle.toLowerCase().includes(q) || (a.bio ?? '').toLowerCase().includes(q),
    );
    return [200, { count: all.length, total: all.length, agents: all }];
  }

  #agent(key) {
    const rec = key.startsWith('@')
      ? [...this.agents.values()].find((a) => a.handle.toLowerCase() === key.slice(1).toLowerCase())
      : this.agents.get(key);
    if (!rec) return [404, { error: 'not_found' }];
    return [200, { agent: rec }];
  }

  #message(body) {
    if (!body) return [400, { error: 'bad_json' }];
    const { to, from, nonce, ciphertext, ts, sig, sentCopy, idempotencyKey } = body;
    if (!TG_ADDRESS_RE.test(to ?? '') || !TG_ADDRESS_RE.test(from ?? '')) {
      return [400, { error: 'bad_address', hint: 'to and from must be TG- addresses' }];
    }
    if (idempotencyKey !== undefined && (typeof idempotencyKey !== 'string' || idempotencyKey.length === 0 || idempotencyKey.length > 128)) {
      return [400, { error: 'bad_idempotency_key', hint: 'idempotencyKey is a non-empty string up to 128 chars' }];
    }
    const sender = this.agents.get(from);
    if (!sender) return [401, { error: 'unknown_sender' }];
    const recipient = this.agents.get(to);
    if (!recipient) return [404, { error: 'unknown_recipient' }];
    if (!verifyFields(messageFields(to, from, nonce, ciphertext, ts), sig, sender.signPublicKey)) {
      return [401, { error: 'bad_signature' }];
    }
    if (this.blocks.get(to)?.has(from)) {
      return [403, { error: 'recipient_blocked_sender', hint: 'the recipient has blocked this address' }];
    }
    // Allowlist strict mode: when on, only listed senders (or self) get through.
    const al = this.allowlists.get(to);
    if (al?.mode && from !== to && !al.entries.has(from)) {
      return [403, { error: 'recipient_not_accepting', hint: 'the recipient only accepts wires from allowlisted senders' }];
    }
    // Idempotency short-circuit: a retried send under the same key collapses to
    // the first delivery's id, delivering (and, on the real relay, charging)
    // nothing more. Checked before the mailbox so a keyed retry is cheap.
    const idemKey = idempotencyKey !== undefined ? `${from}|${idempotencyKey}` : null;
    if (idemKey && this.idempotency.has(idemKey)) {
      return [200, { ok: true, id: this.idempotency.get(idemKey), duplicate: true, idempotent: true }];
    }
    const id = wireId(sig);
    const mailbox = this.mailboxes.get(to) ?? [];
    if (mailbox.some((m) => m.id === id)) return [200, { ok: true, id, duplicate: true }];
    // Per-sender daily quota, mirroring the real relay: the recipient caps how
    // many wires/day any single non-allowlisted sender may deliver. Self-wires
    // and explicitly allowlisted senders are exempt (regardless of strict mode),
    // and the check runs after the duplicate check so a replay never burns quota.
    const perSenderDailyMax = this.quotas.get(to) ?? 0;
    const isExplicitlyAllowed = this.allowlists.get(to)?.entries.has(from) ?? false;
    if (perSenderDailyMax > 0 && from !== to && !isExplicitlyAllowed) {
      const day = new Date().toISOString().slice(0, 10);
      const key = `${day}|${from}|${to}`;
      if ((this.quotaCounts.get(key) ?? 0) >= perSenderDailyMax) {
        return [429, { error: 'sender_quota_exceeded', hint: `the recipient limits non-allowlisted senders to ${perSenderDailyMax} wires/day and you have already reached that` }];
      }
      this.quotaCounts.set(key, (this.quotaCounts.get(key) ?? 0) + 1);
    }
    mailbox.push({ id, to, from, nonce, ciphertext, ts, sig, receivedAt: Date.now(), senderRecord: sender });
    this.mailboxes.set(to, mailbox);
    if (sentCopy) {
      const log = this.sent.get(from) ?? [];
      log.push({ id, to, toHandle: recipient.handle, nonce: sentCopy.nonce, ciphertext: sentCopy.ciphertext, ts, sentAt: Date.now() });
      this.sent.set(from, log);
    }
    // Record the idempotency key only now that the wire is committed, so a send
    // that failed an earlier check (e.g. quota) can still be retried under it.
    if (idemKey) this.idempotency.set(idemKey, id);
    // Flat token estimate, enough for tests to see a number.
    const tokens = Math.max(1, Math.ceil(ciphertext.length / 4));
    return [200, { ok: true, id, tokens, charged: 'free', breakdown: { free: tokens, credits: 0 }, credits: 0 }];
  }

  #inbox(u, headers) {
    const auth = this.#auth('GET', '/v1/inbox', headers, '');
    if (auth.error) return [auth.status, auth];
    const mailbox = this.mailboxes.get(auth.address) ?? [];
    const messages = mailbox.map(({ senderRecord, ...m }) => ({
      ...m,
      sender: this.agents.get(m.from) ?? senderRecord ?? null,
    }));
    return [200, { count: messages.length, messages }];
  }

  #ack(body, headers, rawBody) {
    const auth = this.#auth('POST', '/v1/inbox/ack', headers, rawBody);
    if (auth.error) return [auth.status, auth];
    const ids = new Set((body?.ids ?? []));
    const mailbox = this.mailboxes.get(auth.address) ?? [];
    // Optional signed delivery receipts, verified exactly like the real relay:
    // each must be for a wire being acked and in this mailbox, signed by the
    // acking address over (messageId, sender, recipient, at). Bad ones are
    // skipped silently — a receipt never blocks the ack.
    let receiptsStored = 0;
    if (Array.isArray(body?.receipts) && body.receipts.length) {
      const recipientKey = this.agents.get(auth.address)?.signPublicKey;
      const byId = new Map(mailbox.map((m) => [m.id, m]));
      for (const rc of recipientKey ? body.receipts : []) {
        if (!rc || typeof rc.messageId !== 'string' || typeof rc.sig !== 'string' || typeof rc.at !== 'number') continue;
        if (!ids.has(rc.messageId)) continue;
        const entry = byId.get(rc.messageId);
        if (!entry) continue;
        if (!verifyFields(receiptFields(rc.messageId, entry.from, auth.address, rc.at), rc.sig, recipientKey)) continue;
        const log = this.receipts.get(entry.from) ?? [];
        if (log.some((r) => r.messageId === rc.messageId && r.recipient === auth.address)) continue;
        log.push({ messageId: rc.messageId, recipient: auth.address, from: entry.from, at: rc.at, sig: rc.sig });
        this.receipts.set(entry.from, log);
        receiptsStored += 1;
      }
    }
    const keep = mailbox.filter((m) => !ids.has(m.id));
    this.mailboxes.set(auth.address, keep);
    return [200, { ok: true, removed: mailbox.length - keep.length, remaining: keep.length, ...(receiptsStored ? { receiptsStored } : {}) }];
  }

  #receipts(headers) {
    const auth = this.#auth('GET', '/v1/receipts', headers, '');
    if (auth.error) return [auth.status, auth];
    const receipts = (this.receipts.get(auth.address) ?? [])
      .map((r) => ({ ...r, recipientHandle: this.agents.get(r.recipient)?.handle ?? null }))
      .sort((a, b) => (b.at ?? 0) - (a.at ?? 0));
    return [200, { count: receipts.length, receipts }];
  }

  #sentLog(headers) {
    const auth = this.#auth('GET', '/v1/sent', headers, '');
    if (auth.error) return [auth.status, auth];
    const log = (this.sent.get(auth.address) ?? []).map((m) => ({ ...m, recipient: this.agents.get(m.to) ?? { address: m.to, handle: m.toHandle } }));
    return [200, { count: log.length, messages: log }];
  }

  #credits(headers) {
    const auth = this.#auth('GET', '/v1/credits', headers, '');
    if (auth.error) return [auth.status, auth];
    return [200, { address: auth.address, unit: 'tokens', credits: 0, freeDailyTokens: this.freeDailyTokens, freeUsedToday: 0, freeRemainingToday: this.freeDailyTokens }];
  }

  #block(body, headers, rawBody) {
    const auth = this.#auth('POST', '/v1/blocks', headers, rawBody);
    if (auth.error) return [auth.status, auth];
    if (!TG_ADDRESS_RE.test(body?.address ?? '')) return [400, { error: 'bad_address' }];
    const set = this.blocks.get(auth.address) ?? new Set();
    set.add(body.address);
    this.blocks.set(auth.address, set);
    return [200, { ok: true, blocked: body.address }];
  }

  #unblock(body, headers, rawBody) {
    const auth = this.#auth('POST', '/v1/blocks/remove', headers, rawBody);
    if (auth.error) return [auth.status, auth];
    this.blocks.get(auth.address)?.delete(body?.address);
    return [200, { ok: true, removed: body?.address }];
  }

  #listBlocks(headers) {
    const auth = this.#auth('GET', '/v1/blocks', headers, '');
    if (auth.error) return [auth.status, auth];
    const blocks = [...(this.blocks.get(auth.address) ?? [])].map((address) => ({ address }));
    return [200, { count: blocks.length, blocks }];
  }

  #getAllow(address) {
    let a = this.allowlists.get(address);
    if (!a) {
      a = { mode: false, entries: new Map() };
      this.allowlists.set(address, a);
    }
    return a;
  }

  #allow(body, headers, rawBody) {
    const auth = this.#auth('POST', '/v1/allowlist', headers, rawBody);
    if (auth.error) return [auth.status, auth];
    if (!TG_ADDRESS_RE.test(body?.address ?? '')) return [400, { error: 'bad_address' }];
    if (body.address === auth.address) return [400, { error: 'cannot_allowlist_self' }];
    const a = this.#getAllow(auth.address);
    a.entries.set(body.address, { note: body.note ?? '', at: Date.now() });
    return [200, { ok: true, allowed: body.address, mode: a.mode, count: a.entries.size }];
  }

  #disallow(body, headers, rawBody) {
    const auth = this.#auth('POST', '/v1/allowlist/remove', headers, rawBody);
    if (auth.error) return [auth.status, auth];
    const a = this.#getAllow(auth.address);
    if (!a.entries.delete(body?.address)) return [404, { error: 'not_allowlisted' }];
    return [200, { ok: true, removed: body.address, mode: a.mode, count: a.entries.size }];
  }

  #allowMode(body, headers, rawBody) {
    const auth = this.#auth('POST', '/v1/allowlist/mode', headers, rawBody);
    if (auth.error) return [auth.status, auth];
    if (typeof body?.enabled !== 'boolean') return [400, { error: 'bad_mode' }];
    const a = this.#getAllow(auth.address);
    a.mode = body.enabled;
    const warning = a.mode && a.entries.size === 0
      ? 'allowlist mode is ON but the list is empty — you will accept wires from NO ONE'
      : undefined;
    return [200, { ok: true, mode: a.mode, count: a.entries.size, ...(warning ? { warning } : {}) }];
  }

  #listAllow(headers) {
    const auth = this.#auth('GET', '/v1/allowlist', headers, '');
    if (auth.error) return [auth.status, auth];
    const a = this.#getAllow(auth.address);
    const entries = [...a.entries.entries()].map(([address, e]) => ({
      address, at: e.at, note: e.note, handle: this.agents.get(address)?.handle ?? null,
    }));
    return [200, { mode: a.mode, count: entries.length, entries }];
  }

  #setQuota(body, headers, rawBody) {
    const auth = this.#auth('POST', '/v1/quota', headers, rawBody);
    if (auth.error) return [auth.status, auth];
    if (typeof body?.perSenderDailyMax !== 'number' || body.perSenderDailyMax < 0) {
      return [400, { error: 'bad_quota' }];
    }
    const max = Math.floor(body.perSenderDailyMax);
    this.quotas.set(auth.address, max);
    return [200, { ok: true, perSenderDailyMax: max }];
  }

  #getQuota(headers) {
    const auth = this.#auth('GET', '/v1/quota', headers, '');
    if (auth.error) return [auth.status, auth];
    return [200, { perSenderDailyMax: this.quotas.get(auth.address) ?? 0 }];
  }

  // Webhook registration is stored and returned like the real relay, but the
  // in-memory mock does NOT deliver (there's no network) — use a live relay to
  // exercise actual push delivery. This lets an agent's setWebhook/getWebhook/
  // removeWebhook plumbing be tested offline.
  #setWebhook(body, headers, rawBody) {
    const auth = this.#auth('POST', '/v1/webhook', headers, rawBody);
    if (auth.error) return [auth.status, auth];
    const url = body?.url;
    if (typeof url !== 'string' || !url) return [400, { error: 'bad_webhook_url', hint: 'url is required (https)' }];
    let parsed;
    try {
      parsed = new URL(url);
    } catch {
      return [400, { error: 'bad_webhook_url', hint: 'url must be a valid absolute URL' }];
    }
    if (parsed.protocol !== 'https:') return [400, { error: 'bad_webhook_url', reason: 'not_https', hint: 'webhook url must be https' }];
    let secret = body?.secret;
    if (secret !== undefined) {
      if (typeof secret !== 'string' || secret.length < 16 || secret.length > 128) {
        return [400, { error: 'bad_webhook_secret', hint: 'secret is an optional string 16–128 chars; omit it to have one generated' }];
      }
    } else {
      secret = crypto.randomBytes(32).toString('hex');
    }
    this.webhooks.set(auth.address, { url: parsed.href, secret, createdAt: Date.now(), failures: 0, disabled: false });
    return [200, { ok: true, url: parsed.href, secret, note: 'mock relay stores webhooks but does not deliver them; use a live relay for push delivery' }];
  }

  #getWebhook(headers) {
    const auth = this.#auth('GET', '/v1/webhook', headers, '');
    if (auth.error) return [auth.status, auth];
    const hook = this.webhooks.get(auth.address);
    if (!hook) return [404, { error: 'no_webhook', hint: 'register one with POST /v1/webhook {url}' }];
    return [200, { url: hook.url, createdAt: hook.createdAt, failures: hook.failures, disabled: hook.disabled }];
  }

  #removeWebhook(headers, rawBody) {
    const auth = this.#auth('POST', '/v1/webhook/remove', headers, rawBody);
    if (auth.error) return [auth.status, auth];
    if (!this.webhooks.delete(auth.address)) return [404, { error: 'no_webhook', hint: 'nothing to remove' }];
    return [200, { ok: true, removed: true }];
  }

  // Verifies a signed request the same way the real relay does: the address
  // header names the signer, the ts is fresh, and the signature covers
  // (method, path, sha256(body), ts) under that address's registered key.
  #auth(method, path, headers, rawBody) {
    const address = headers['x-telegraph-address'];
    const ts = Number(headers['x-telegraph-ts']);
    const sig = headers['x-telegraph-sig'];
    if (!address || !sig || !Number.isFinite(ts)) {
      return { error: 'unauthorized', status: 401, hint: 'signed request needs x-telegraph-address/ts/sig' };
    }
    if (Math.abs(Date.now() - ts) > AUTH_WINDOW_MS) {
      return { error: 'stale_ts', status: 401, hint: 'auth ts outside ±5 min' };
    }
    const agent = this.agents.get(address);
    if (!agent) return { error: 'unknown_sender', status: 401 };
    const bodyHash = crypto.createHash('sha256').update(rawBody ?? '').digest('hex');
    if (!verifyFields(authFields(method, path, bodyHash, ts), sig, agent.signPublicKey)) {
      return { error: 'bad_signature', status: 401 };
    }
    return { address };
  }
}

function method(route) {
  return route.split(' ')[0];
}

function normalizeHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers)) out[k.toLowerCase()] = v;
  return out;
}

function wireId(sig) {
  return crypto.createHash('sha256').update(fromB64(sig)).digest('hex').slice(0, 24);
}

function mkResponse(status, payload) {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return payload;
    },
  };
}
