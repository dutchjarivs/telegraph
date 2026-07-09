// Telegraph relay server — a dumb, honest switchboard.
// It stores and forwards sealed envelopes. It cannot read them.
// Billing: every agent gets a free daily allowance of wires; beyond that,
// sending costs one prepaid credit per wire. Reading is always free.
import http from 'node:http';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { Storage } from './storage.js';
import {
  registerFields,
  messageFields,
  authFields,
  verifyFields,
  deriveAddress,
  fromB64,
} from './crypto.js';

export const DEFAULT_LIMITS = {
  bodyBytes: 64 * 1024,
  ciphertextB64: 16 * 1024, // one wire is a short message
  bioChars: 280,
  handleRe: /^[a-z0-9][a-z0-9_-]{1,31}$/i,
  authWindowMs: 5 * 60_000,
  msgWindowMs: 10 * 60_000,
  mailboxCap: 500,
  messageTtlMs: 0, // 0 = wires never expire; > 0 drops mailbox wires older than this
  rate: { windowMs: 60_000, max: 60 },
  registerRate: { windowMs: 60 * 60_000, max: 5 }, // new identities per client IP per hour (anti-sybil)
  maxCapabilities: 16,
  directoryPageMax: 200, // largest allowed ?limit= on GET /v1/directory
  capabilityChars: 48,
  freeDailyTokens: 500, // free tokens per sender per UTC day
  bytesPerToken: 4, // token estimate: relay can't read plaintext, so ~4 ciphertext bytes ≈ 1 token
  sentLogCap: 200, // self-sealed sent copies kept per agent (ring buffer, not billed)
  reportRate: { windowMs: 24 * 60 * 60_000, max: 20 }, // abuse reports per reporter per day
  reportCommentChars: 500,
  // Distinct reporters (non-dismissed reports) before an agent is publicly
  // flagged in the directory. Reports need cryptographic evidence of a wire
  // from the reported sender, so false-flagging requires the target to have
  // actually wired every accuser.
  flagThreshold: 3,
};

export const REPORT_REASONS = ['spam', 'scam', 'phishing', 'impersonation', 'abuse', 'other'];

export const PRICING = {
  currency: 'USD',
  processor: 'Stripe',
  unit: 'token',
  usdPerMillionTokens: 1,
  tokenEstimate:
    '1 token ≈ 4 bytes of message. The relay cannot read plaintext (E2EE), so tokens are estimated from ciphertext size. Minimum 1 token per wire.',
  free: { tokensPerDay: 500, note: 'per agent, resets at UTC midnight; receiving is always free' },
  bundles: [
    { tokens: 1_000_000, usd: 1 },
    { tokens: 25_000_000, usd: 19 },
    { tokens: 1_000_000_000, usd: 499 },
  ],
  creditsExpire: false,
  howToBuy:
    'Past the free daily allowance, buy prepaid token credits by card through Stripe Checkout (see the "checkout" field of this pricing response for the link). Enter your TG- address in the checkout form so the relay credits the right account automatically. Credits never expire and are spent after your free allowance. No subscription, no tab — you only buy what you need.',
};

// Checkout amounts map to bundles exactly (bundles carry volume discounts);
// any other amount falls back to the base rate: $1 per 1M tokens = 10k tokens/cent.
const BUNDLE_TOKENS_BY_CENTS = Object.fromEntries(PRICING.bundles.map((b) => [b.usd * 100, b.tokens]));

function tokensForCents(cents) {
  if (!Number.isInteger(cents) || cents <= 0) return 0;
  return BUNDLE_TOKENS_BY_CENTS[cents] ?? cents * 10_000;
}

const TG_ADDRESS_RE = /^TG-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/;

export function createServer({
  dataDir,
  limits = {},
  adminToken = process.env.TELEGRAPH_ADMIN_TOKEN,
  // Set to the endpoint signing secret (whsec_...) from the Stripe dashboard to
  // enable automated credit grants on checkout; disabled (403) when unset.
  stripeWebhookSecret = process.env.STRIPE_WEBHOOK_SECRET,
  // The Stripe Payment Link / Checkout URL agents are sent to buy credits. When
  // unset, /v1/pricing reports checkout as not-yet-enabled on this relay.
  checkoutUrl = process.env.TELEGRAPH_CHECKOUT_URL,
  // Only trust x-forwarded-for when a reverse proxy (Caddy, cloudflared) sets it;
  // trusting it on a directly exposed relay lets clients spoof their IP.
  trustProxy = process.env.TELEGRAPH_TRUST_PROXY === '1',
  // Opt-in one-line access log per request (method, path, status, ms). Never
  // logs bodies, query strings, or auth headers. Off unless TELEGRAPH_LOG=1.
  logRequests = process.env.TELEGRAPH_LOG === '1',
  log = console.log,
} = {}) {
  const LIMITS = { ...DEFAULT_LIMITS, ...limits };
  // Env-configured mailbox TTL (in days), unless the caller set it explicitly.
  const envTtlDays = Number(process.env.TELEGRAPH_MESSAGE_TTL_DAYS);
  if (!('messageTtlMs' in limits) && envTtlDays > 0) LIMITS.messageTtlMs = envTtlDays * 86_400_000;
  const store = new Storage(dataDir);
  // With a TTL set, expired wires are pruned lazily on every mailbox load —
  // they stop being visible, deliverable-against (cap space frees up), and
  // reportable the moment they age out, with no background sweeper to run.
  const loadMailbox = (address) => {
    const mailbox = store.loadMailbox(address);
    if (!(LIMITS.messageTtlMs > 0)) return mailbox;
    const cutoff = Date.now() - LIMITS.messageTtlMs;
    const fresh = mailbox.filter((m) => m.receivedAt >= cutoff);
    if (fresh.length !== mailbox.length) store.saveMailbox(address, fresh);
    return fresh;
  };
  const rateMap = new Map();
  const registerMap = new Map();
  const reportMap = new Map();

  // Standing: how an address looks to the moderation system. Flagging is
  // derived from reports on every read (never stored), so dismissing a report
  // clears the flag with no extra bookkeeping.
  function reportStats(address) {
    const all = store.listReports().filter((r) => r.reported === address);
    const active = all.filter((r) => r.status !== 'dismissed');
    const distinctReporters = new Set(active.map((r) => r.reporter)).size;
    return {
      total: all.length,
      open: active.filter((r) => r.status === 'open').length,
      distinctReporters,
      flagged: distinctReporters >= LIMITS.flagThreshold,
    };
  }

  // Public decoration: agents everywhere else see the record verbatim, plus
  // warning fields when they apply. Extra fields never break record
  // verification — signatures cover only the registration fields.
  function decorateAgent(agent) {
    if (!agent) return agent;
    const out = { ...agent };
    if (reportStats(agent.address).flagged) {
      out.flagged = true;
      out.flagWarning = 'multiple agents reported wires from this address as spam or scam — verify before trusting';
    }
    if (store.getModeration(agent.address).suspended) out.suspended = true;
    return out;
  }
  let pkgVersion = '0';
  try {
    pkgVersion = JSON.parse(fs.readFileSync(new URL('../package.json', import.meta.url), 'utf8')).version ?? '0';
  } catch { /* keep default */ }
  const siteFile = new URL('../site/index.html', import.meta.url);
  const dashboardFile = new URL('../site/dashboard.html', import.meta.url);
  const ownerFile = new URL('../site/owner.html', import.meta.url);
  const naclFile = new URL('../node_modules/tweetnacl/nacl-fast.min.js', import.meta.url);
  const llmsFile = new URL('../llms.txt', import.meta.url);
  const protocolFile = new URL('../docs/PROTOCOL.md', import.meta.url);
  const readmeFile = new URL('../README.md', import.meta.url);

  const server = http.createServer((req, res) => {
    if (logRequests) {
      const startedAt = Date.now();
      const method = req.method;
      // pathname only — never the query string (could carry a search term).
      const pathname = (req.url ?? '').split('?')[0];
      res.on('finish', () => {
        log(`[telegraph] ${method} ${pathname} ${res.statusCode} ${Date.now() - startedAt}ms`);
      });
    }
    handle(req, res).catch((err) => {
      const status = Number.isInteger(err?.status) ? err.status : 500;
      // Don't leak internal error text (fs paths, stack messages) to clients.
      // 413 carries a safe, useful limit message; everything else is generic
      // and the detail is logged server-side for the operator.
      if (status >= 500) {
        console.error('[telegraph] internal error:', err?.stack ?? err);
        return send(res, status, { error: 'internal_error' });
      }
      send(res, status, { error: status === 413 ? 'too_large' : 'bad_request', detail: String(err?.message ?? err) });
    });
  });

  // Rate-limit state is a per-key sliding window; without eviction the maps
  // grow for every distinct sender/IP/reporter ever seen (a slow memory-
  // exhaustion vector). Sweep fully-expired keys on a timer — unref'd so it
  // never holds the process open, cleared when the server closes.
  const rateLimiters = [
    [rateMap, LIMITS.rate.windowMs],
    [registerMap, LIMITS.registerRate.windowMs],
    [reportMap, LIMITS.reportRate.windowMs],
  ];
  const sweepTimer = setInterval(() => {
    const now = Date.now();
    for (const [map, windowMs] of rateLimiters) {
      for (const [k, hits] of map) {
        if (!hits.length || now - hits[hits.length - 1] >= windowMs) map.delete(k);
      }
    }
  }, 10 * 60_000);
  if (typeof sweepTimer.unref === 'function') sweepTimer.unref();
  server.on('close', () => clearInterval(sweepTimer));

  async function handle(req, res) {
    res.setHeader('access-control-allow-origin', '*');
    res.setHeader('access-control-allow-headers', 'content-type,x-telegraph-address,x-telegraph-ts,x-telegraph-sig,x-telegraph-admin');
    if (req.method === 'OPTIONS') {
      res.writeHead(204, { 'access-control-allow-methods': 'GET,POST,OPTIONS' });
      return res.end();
    }

    const url = new URL(req.url, 'http://localhost');
    const route = `${req.method} ${url.pathname}`;

    // Content negotiation at the root: browsers get the site, agents get JSON.
    if (route === 'GET /' || route === 'GET /index.html') {
      const wantsHtml = (req.headers.accept ?? '').includes('text/html');
      if (wantsHtml && fs.existsSync(siteFile)) {
        res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
        return res.end(fs.readFileSync(siteFile));
      }
      return send(res, 200, {
        service: 'telegraph',
        tagline: 'SMS for agents — end-to-end encrypted wires',
        docs: '/llms.txt',
        onboard: '/v1/onboard',
        pricing: '/v1/pricing',
        health: '/v1/health',
      });
    }

    // Operator dashboard: the page itself holds no secrets — every data call
    // from it is gated by the admin token the operator types into the browser.
    if (route === 'GET /dashboard' && fs.existsSync(dashboardFile)) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(fs.readFileSync(dashboardFile));
    }

    // Owner console: a human loads their agent's identity file into the page;
    // signing and decryption happen in the browser, keys never reach the relay.
    if (route === 'GET /owner' && fs.existsSync(ownerFile)) {
      res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
      return res.end(fs.readFileSync(ownerFile));
    }

    if (route === 'GET /vendor/nacl-fast.min.js' && fs.existsSync(naclFile)) {
      res.writeHead(200, { 'content-type': 'text/javascript; charset=utf-8', 'cache-control': 'public, max-age=86400' });
      return res.end(fs.readFileSync(naclFile));
    }

    if (route === 'GET /llms.txt' && fs.existsSync(llmsFile)) {
      res.writeHead(200, { 'content-type': 'text/plain; charset=utf-8' });
      return res.end(fs.readFileSync(llmsFile));
    }

    // The docs llms.txt links to must actually be reachable from the relay —
    // remote agents have no repo to read them from.
    if ((route === 'GET /docs/PROTOCOL.md' || route === 'GET /PROTOCOL.md') && fs.existsSync(protocolFile)) {
      res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8' });
      return res.end(fs.readFileSync(protocolFile));
    }

    if (route === 'GET /README.md' && fs.existsSync(readmeFile)) {
      res.writeHead(200, { 'content-type': 'text/markdown; charset=utf-8' });
      return res.end(fs.readFileSync(readmeFile));
    }

    if (route === 'GET /v1/health') {
      // Cheap liveness + at-a-glance stats for uptime monitors and the operator.
      // `version` is the protocol/API version (stable); `release` is the build.
      return send(res, 200, {
        ok: true,
        service: 'telegraph',
        version: 1,
        release: pkgVersion,
        uptimeSeconds: Math.round(process.uptime()),
        agents: store.listAgents().length,
        now: Date.now(),
      });
    }

    if (route === 'GET /v1/onboard') {
      // Agentic signup: everything an agent needs to go from nothing to
      // registered, readable by machine. No account, no email, no human.
      return send(res, 200, {
        service: 'telegraph',
        summary:
          'Signup is self-service and takes one request. Your identity is a keypair you generate locally; your address is derived from it. No account, no email, no approval step.',
        quickest: {
          cli: 'telegraph signup --handle <name> --server <this relay URL>',
          note: 'one command: generates keys locally, registers, reports your free balance. The CLI ships with the Telegraph repo (git clone + npm install); an npm package is on the roadmap, not published yet.',
        },
        diy: {
          summary: 'Any language with an Ed25519/X25519 NaCl library can sign up with plain HTTP.',
          steps: [
            '1. Generate an Ed25519 signing keypair and an X25519 box keypair (e.g. nacl.sign.keyPair(), nacl.box.keyPair()).',
            '2. Your address is TG- plus Crockford-base32 of the first 10 bytes of SHA-512(signPublicKey), grouped in 4s — the relay derives it, you never pick it.',
            '3. Sign the canonical register payload: JSON.stringify(["telegraph-register-v1", handle, signPublicKeyB64, boxPublicKeyB64, bio, capabilities, ts]) with your signing secret key (detached Ed25519, base64).',
            '4. POST /v1/register with {handle, signPublicKey, boxPublicKey, bio, capabilities, ts, sig}. ts is current unix ms (±5 min).',
            '5. You are live: GET /v1/directory to find agents, POST /v1/messages to wire them, GET /v1/inbox (signed) to read.',
          ],
          fullSpec: '/docs/PROTOCOL.md — the complete wire format, served by this relay',
        },
        sendingWires: {
          summary:
            'Every signature is detached Ed25519 (base64) over the UTF-8 bytes of JSON.stringify of a fixed-order array — standard JSON.stringify, no whitespace.',
          steps: [
            "1. Fetch the recipient: GET /v1/agents/@handle. Verify their record: their sig over JSON.stringify([\"telegraph-register-v1\", handle, signPublicKey, boxPublicKey, bio, capabilities, ts]) checks against their signPublicKey, and their address re-derives from it.",
            '2. Encrypt: nonce = 24 random bytes; ciphertext = nacl.box(utf8(plaintext), nonce, recipientBoxPublicKey, yourBoxSecretKey). Base64 both.',
            '3. Sign: sig = Ed25519 over utf8(JSON.stringify(["telegraph-message-v1", to, from, nonce, ciphertext, ts])) with your signSecretKey. to and from are TG- addresses, nonce and ciphertext are the base64 strings from step 2, ts is unix ms.',
            '4. POST /v1/messages with {to, from, nonce, ciphertext, ts, sig}.',
            '5. Read mail: GET /v1/inbox with headers x-telegraph-address, x-telegraph-ts, x-telegraph-sig, where sig = Ed25519 over utf8(JSON.stringify(["telegraph-auth-v1", "GET", "/v1/inbox", bodyHashHex, ts])). bodyHashHex is lowercase hex SHA-256 of the raw request body — for GET, of the empty string: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855.',
            '6. Acknowledge processed wires: POST /v1/inbox/ack with {"ids": [...]}, same auth headers, bodyHashHex over the exact raw body.',
          ],
        },
        rules: {
          handle: '2-32 chars: a-z 0-9 _ - (case-insensitive, unique)',
          registrationRateLimit: `${LIMITS.registerRate.max} new identities per IP per ${Math.round(LIMITS.registerRate.windowMs / 60_000)} min; updating an existing registration is never throttled`,
          freeTier: `${LIMITS.freeDailyTokens} free tokens/day, resets at UTC midnight; receiving is always free`,
          payment: 'past the free daily allowance: buy prepaid token credits by card via Stripe Checkout — see GET /v1/pricing for the link. Credits never expire; you only buy what you need.',
          abuse: `spam or scam wires: report them via POST /v1/reports (signed) with the wire's messageId (still in your mailbox) or its full envelope from your inbox, plus a reason (${REPORT_REASONS.join('|')}). Reports carry cryptographic proof the sender wired you. Agents reported by ${LIMITS.flagThreshold}+ distinct reporters are flagged in the directory; the operator can suspend senders. Directory records may carry "flagged" or "suspended" — check before trusting a stranger.`,
        },
        keySafety: 'Your secret keys never leave your machine and the relay never sees them. Losing them means losing the identity — store them like credentials.',
      });
    }

    if (route === 'GET /v1/pricing') {
      return send(res, 200, {
        ...PRICING,
        free: { ...PRICING.free, tokensPerDay: LIMITS.freeDailyTokens },
        checkout: checkoutUrl
          ? { url: checkoutUrl, note: 'Stripe Checkout — enter your TG- address in the form so the credits land on your account.' }
          : { url: null, note: 'card checkout is not enabled on this relay yet — contact the operator' },
      });
    }

    if (route === 'POST /v1/register') {
      const raw = await readRaw(req);
      const body = parseJson(raw);
      if (!body) return send(res, 400, { error: 'bad_json' });
      const { handle: h, signPublicKey, boxPublicKey, bio = '', capabilities = [], ts, sig } = body;
      if (typeof h !== 'string' || !LIMITS.handleRe.test(h)) {
        return send(res, 400, { error: 'bad_handle', hint: '2-32 chars: a-z 0-9 _ - (must start alphanumeric)' });
      }
      if (typeof bio !== 'string' || bio.length > LIMITS.bioChars) {
        return send(res, 400, { error: 'bad_bio', hint: `string, max ${LIMITS.bioChars} chars` });
      }
      if (
        !Array.isArray(capabilities) ||
        capabilities.length > LIMITS.maxCapabilities ||
        capabilities.some((c) => typeof c !== 'string' || c.length === 0 || c.length > LIMITS.capabilityChars)
      ) {
        return send(res, 400, { error: 'bad_capabilities', hint: `array of up to ${LIMITS.maxCapabilities} short strings` });
      }
      if (!validKeyB64(signPublicKey) || !validKeyB64(boxPublicKey)) {
        return send(res, 400, { error: 'bad_keys', hint: 'signPublicKey and boxPublicKey must be base64 of 32 bytes' });
      }
      if (!freshTs(ts, LIMITS.authWindowMs)) {
        return send(res, 400, { error: 'stale_ts', hint: 'ts must be current unix ms' });
      }
      if (!verifyFields(registerFields(h, signPublicKey, boxPublicKey, bio, capabilities, ts), sig, signPublicKey)) {
        return send(res, 401, {
          error: 'bad_signature',
          hint: 'sig must be detached Ed25519 (base64) over utf8(JSON.stringify(["telegraph-register-v1", handle, signPublicKey, boxPublicKey, bio, capabilities, ts])) signed with your signSecretKey — see /v1/onboard',
        });
      }
      const address = deriveAddress(signPublicKey);
      const existingByHandle = store.findByHandle(h);
      if (existingByHandle && existingByHandle.address !== address) {
        return send(res, 409, { error: 'handle_taken' });
      }
      const prev = store.getAgent(address);
      // Directory records are public and carry their ts + sig — the full
      // register payload. Refusing older-than-current ts means a replayed
      // stale payload can't revert a newer update within the freshness window.
      if (prev && typeof prev.ts === 'number' && ts < prev.ts) {
        return send(res, 409, { error: 'stale_registration', hint: 'a newer registration exists for this address — sign a fresh payload with a current ts' });
      }
      // Anti-sybil: new identities are throttled per client IP. Updating an
      // existing registration (same address) is always allowed.
      if (!prev && !allowHit(registerMap, clientIp(req), LIMITS.registerRate)) {
        return send(res, 429, {
          error: 'registration_rate_limited',
          hint: `max ${LIMITS.registerRate.max} new registrations per IP per ${Math.round(LIMITS.registerRate.windowMs / 60_000)} min`,
        });
      }
      store.upsertAgent({
        address,
        handle: h,
        signPublicKey,
        boxPublicKey,
        bio,
        capabilities,
        ts,
        sig,
        registeredAt: prev?.registeredAt ?? Date.now(),
        updatedAt: Date.now(),
      });
      return send(res, 200, { ok: true, address, handle: h });
    }

    if (route === 'GET /v1/directory') {
      const q = (url.searchParams.get('q') ?? '').toLowerCase();
      // Suspended agents are delisted from discovery; direct lookup by address
      // or handle still works (labelled), so correspondents can see why.
      let agents = store.listAgents().filter((a) => !store.getModeration(a.address).suspended);
      if (q) {
        agents = agents.filter((a) =>
          [a.handle, a.bio, ...(a.capabilities ?? [])].join(' ').toLowerCase().includes(q),
        );
      }
      // Stable oldest-first order so offset paging never skips or repeats an
      // agent when new registrations land between pages.
      agents.sort((a, b) => (a.registeredAt ?? 0) - (b.registeredAt ?? 0) || (a.address < b.address ? -1 : 1));
      const total = agents.length;
      // Pagination is opt-in: without limit/offset the full directory returns,
      // exactly as before. limit is capped so one call can't be made huge.
      const limitRaw = url.searchParams.get('limit');
      const offsetRaw = url.searchParams.get('offset');
      const limit = limitRaw === null ? null : Number(limitRaw);
      const offset = offsetRaw === null ? 0 : Number(offsetRaw);
      if (limit !== null && (!Number.isInteger(limit) || limit < 1 || limit > LIMITS.directoryPageMax)) {
        return send(res, 400, { error: 'bad_limit', hint: `limit must be an integer 1..${LIMITS.directoryPageMax}` });
      }
      if (!Number.isInteger(offset) || offset < 0) {
        return send(res, 400, { error: 'bad_offset', hint: 'offset must be an integer >= 0' });
      }
      const page = limit === null ? agents.slice(offset) : agents.slice(offset, offset + limit);
      const nextOffset = limit !== null && offset + limit < total ? offset + limit : null;
      return send(res, 200, {
        count: page.length,
        total,
        offset,
        ...(limit !== null ? { limit } : {}),
        ...(nextOffset !== null ? { nextOffset } : {}),
        agents: page.map(decorateAgent),
      });
    }

    if (req.method === 'GET' && url.pathname.startsWith('/v1/agents/')) {
      let key;
      try {
        key = decodeURIComponent(url.pathname.slice('/v1/agents/'.length));
      } catch {
        return send(res, 400, { error: 'bad_request', hint: 'malformed url encoding' });
      }
      const agent = key.startsWith('TG-')
        ? store.getAgent(key)
        : store.findByHandle(key.replace(/^@/, ''));
      if (!agent) return send(res, 404, { error: 'not_found' });
      return send(res, 200, { agent: decorateAgent(agent) });
    }

    if (route === 'POST /v1/messages') {
      const raw = await readRaw(req);
      const body = parseJson(raw);
      if (!body) return send(res, 400, { error: 'bad_json' });
      const { to, from, nonce, ciphertext, ts, sig, sentCopy } = body;
      const missing = ['to', 'from', 'nonce', 'ciphertext', 'ts', 'sig'].filter(
        (k) => body[k] === undefined || body[k] === null || body[k] === '',
      );
      if (missing.length) {
        return send(res, 400, {
          error: 'missing_fields',
          hint: `required: to, from, nonce, ciphertext, ts, sig — missing: ${missing.join(', ')}. See /v1/onboard for the wire format.`,
        });
      }
      // Addresses must be well-formed before any lookup — a bare object-key
      // lookup on values like "__proto__" or "constructor" would otherwise
      // resolve to a prototype member and slip past the existence checks.
      if (!TG_ADDRESS_RE.test(to) || !TG_ADDRESS_RE.test(from)) {
        return send(res, 400, { error: 'bad_address', hint: 'to and from must be TG- addresses' });
      }
      if (typeof ciphertext !== 'string' || ciphertext.length === 0) {
        return send(res, 400, { error: 'bad_ciphertext', hint: 'base64 string from nacl.box' });
      }
      if (ciphertext.length > LIMITS.ciphertextB64) {
        return send(res, 413, { error: 'too_long', hint: 'a wire is a short message — split it up' });
      }
      if (typeof nonce !== 'string' || safeB64Len(nonce) !== 24) {
        return send(res, 400, { error: 'bad_nonce', hint: 'base64 of 24 bytes' });
      }
      // Optional self-sealed copy for the sender's own history. Encrypted to
      // the sender's box key — the relay can't read it any more than the wire.
      if (sentCopy !== undefined) {
        if (
          typeof sentCopy !== 'object' || sentCopy === null ||
          typeof sentCopy.ciphertext !== 'string' || sentCopy.ciphertext.length === 0 ||
          sentCopy.ciphertext.length > LIMITS.ciphertextB64 ||
          typeof sentCopy.nonce !== 'string' || safeB64Len(sentCopy.nonce) !== 24
        ) {
          return send(res, 400, { error: 'bad_sent_copy', hint: 'sentCopy is {nonce, ciphertext}: the wire sealed to your own box key' });
        }
      }
      if (!freshTs(ts, LIMITS.msgWindowMs)) {
        return send(res, 400, { error: 'stale_ts' });
      }
      const sender = store.getAgent(from);
      if (!sender) return send(res, 401, { error: 'unknown_sender', hint: 'register first: POST /v1/register' });
      if (store.getModeration(from).suspended) {
        return send(res, 403, {
          error: 'sender_suspended',
          hint: 'this address is suspended from sending after abuse reports — contact the relay operator to appeal; your inbox still works',
        });
      }
      const recipient = store.getAgent(to);
      if (!recipient) return send(res, 404, { error: 'unknown_recipient' });
      if (!verifyFields(messageFields(to, from, nonce, ciphertext, ts), sig, sender.signPublicKey)) {
        return send(res, 401, {
          error: 'bad_signature',
          hint: 'sig must be detached Ed25519 (base64) over utf8(JSON.stringify(["telegraph-message-v1", to, from, nonce, ciphertext, ts])) signed with the signSecretKey of the registered sender — full spec: /docs/PROTOCOL.md',
        });
      }
      if (!allowRate(from)) {
        return send(res, 429, { error: 'rate_limited', hint: `max ${LIMITS.rate.max} wires/min` });
      }
      const mailbox = loadMailbox(to);
      // Duplicate check before the cap check: resending an already-delivered
      // wire into a full mailbox is still a duplicate, not a 507.
      // The seen ledger extends dedup past ack: without it, anyone holding the
      // envelope (including the recipient) could replay it after the mailbox
      // is cleared and bill the sender again for every replay until the ts
      // window closes. Entries older than the replayable window are pruned.
      const id = wireId(sig);
      const seen = store.loadSeen(to);
      const seenCutoff = Date.now() - 2 * LIMITS.msgWindowMs;
      let pruned = false;
      for (const [k, at] of Object.entries(seen)) {
        if (at < seenCutoff) {
          delete seen[k];
          pruned = true;
        }
      }
      if (mailbox.some((m) => m.id === id) || Object.hasOwn(seen, id)) {
        if (pruned) store.saveSeen(to, seen);
        return send(res, 200, { ok: true, id, duplicate: true });
      }
      if (mailbox.length >= LIMITS.mailboxCap) {
        return send(res, 507, { error: 'mailbox_full', hint: 'recipient must fetch and ack before receiving more' });
      }
      // Charge only after every check has passed; duplicates are never charged.
      const today = new Date().toISOString().slice(0, 10);
      const bill = store.getBilling(from);
      if (bill.day !== today) {
        bill.day = today;
        bill.used = 0;
      }
      // Token metering: the relay can't read plaintext, so it estimates tokens
      // from ciphertext size (nacl.box adds 16 bytes of overhead).
      const tokens = Math.max(1, Math.ceil(Math.max(1, safeB64Len(ciphertext) - 16) / LIMITS.bytesPerToken));
      // Charge order: free daily allowance → prepaid credits. Prepaid only:
      // there is no tab or debt — a wire is committed only if free + credits
      // fully cover it, otherwise it's rejected with 402 and nothing changes.
      const fromFree = Math.min(tokens, Math.max(0, LIMITS.freeDailyTokens - bill.used));
      const fromCredits = Math.min(tokens - fromFree, bill.credits);
      if (fromFree + fromCredits < tokens) {
        return send(res, 402, {
          error: 'payment_required',
          hint: `wire costs ${tokens} tokens; your free daily allowance is used up and prepaid credits are exhausted — buy more token credits by card, see GET /v1/pricing`,
        });
      }
      bill.used += fromFree;
      bill.credits -= fromCredits;
      const charged = fromFree && fromCredits ? 'mixed' : fromFree ? 'free' : 'credit';
      store.setBilling(from, bill);
      // senderRecord: snapshot of the sender's signed directory record at
      // delivery time. Without it, removing the sender (or a future key
      // rotation) makes queued wires undecryptable — the recipient needs the
      // sender's box key to open them. The record is self-signed, so the
      // recipient can still verify it even after the live record is gone.
      mailbox.push({ id, to, from, nonce, ciphertext, ts, sig, receivedAt: Date.now(), senderRecord: sender });
      store.saveMailbox(to, mailbox);
      seen[id] = Date.now();
      store.saveSeen(to, seen);
      if (sentCopy) {
        store.appendSent(from, {
          id,
          to,
          toHandle: recipient.handle, // survives recipient removal
          nonce: sentCopy.nonce,
          ciphertext: sentCopy.ciphertext,
          ts,
          sentAt: Date.now(),
        }, LIMITS.sentLogCap);
      }
      return send(res, 200, {
        ok: true,
        id,
        tokens,
        charged,
        breakdown: { free: fromFree, credits: fromCredits },
        credits: bill.credits,
      });
    }

    if (route === 'GET /v1/inbox') {
      const auth = checkAuth(req, url.pathname, sha256hex(''));
      if (auth.error) return send(res, auth.status, { error: auth.error, ...(auth.hint ? { hint: auth.hint } : {}) });
      const mailbox = loadMailbox(auth.address);
      const messages = mailbox.map(({ senderRecord, ...m }) => ({
        ...m,
        // Live record first (fresh bio/handle), delivery-time snapshot as the
        // fallback so wires stay decryptable after the sender is removed.
        // Decoration warns recipients when the sender has since been flagged.
        sender: decorateAgent(store.getAgent(m.from)) ?? senderRecord ?? null,
      }));
      return send(res, 200, { count: messages.length, messages });
    }

    if (route === 'GET /v1/sent') {
      const auth = checkAuth(req, url.pathname, sha256hex(''));
      if (auth.error) return send(res, auth.status, { error: auth.error, ...(auth.hint ? { hint: auth.hint } : {}) });
      const log = store.loadSent(auth.address);
      const messages = log.map((m) => ({
        ...m,
        recipient: store.getAgent(m.to) ?? (m.toHandle ? { address: m.to, handle: m.toHandle } : null),
      }));
      return send(res, 200, { count: messages.length, messages });
    }

    if (route === 'POST /v1/inbox/ack') {
      const raw = await readRaw(req);
      const auth = checkAuth(req, url.pathname, sha256hex(raw));
      if (auth.error) return send(res, auth.status, { error: auth.error, ...(auth.hint ? { hint: auth.hint } : {}) });
      const body = parseJson(raw);
      if (!body || !Array.isArray(body.ids) || body.ids.some((i) => typeof i !== 'string')) {
        return send(res, 400, { error: 'bad_ids', hint: 'body: {"ids": ["..."]}' });
      }
      const ids = new Set(body.ids);
      const mailbox = loadMailbox(auth.address);
      const keep = mailbox.filter((m) => !ids.has(m.id));
      store.saveMailbox(auth.address, keep);
      return send(res, 200, { ok: true, removed: mailbox.length - keep.length, remaining: keep.length });
    }

    if (route === 'GET /v1/credits') {
      const auth = checkAuth(req, url.pathname, sha256hex(''));
      if (auth.error) return send(res, auth.status, { error: auth.error, ...(auth.hint ? { hint: auth.hint } : {}) });
      const today = new Date().toISOString().slice(0, 10);
      const bill = store.getBilling(auth.address);
      const usedToday = bill.day === today ? bill.used : 0;
      return send(res, 200, {
        address: auth.address,
        unit: 'tokens',
        credits: bill.credits,
        freeDailyTokens: LIMITS.freeDailyTokens,
        freeUsedToday: usedToday,
        freeRemainingToday: Math.max(0, LIMITS.freeDailyTokens - usedToday),
      });
    }

    if (route === 'POST /v1/reports') {
      // Report a wire you received as spam/scam. The relay can't read wires,
      // so moderation runs on receipts, not contents: every report must prove
      // the reported sender actually wired the reporter. Two forms of proof —
      //   messageId: the wire is still in your mailbox (relay verified it at delivery)
      //   envelope:  the full signed envelope from GET /v1/inbox, re-verified here,
      //              so you can still report after acking.
      const raw = await readRaw(req);
      const auth = checkAuth(req, url.pathname, sha256hex(raw));
      if (auth.error) return send(res, auth.status, { error: auth.error, ...(auth.hint ? { hint: auth.hint } : {}) });
      const body = parseJson(raw);
      if (!body) return send(res, 400, { error: 'bad_json' });
      const { messageId, envelope, reason, comment = '' } = body;
      if (!REPORT_REASONS.includes(reason)) {
        return send(res, 400, { error: 'bad_reason', hint: `reason must be one of: ${REPORT_REASONS.join(', ')}` });
      }
      if (typeof comment !== 'string' || comment.length > LIMITS.reportCommentChars) {
        return send(res, 400, { error: 'bad_comment', hint: `optional string, max ${LIMITS.reportCommentChars} chars` });
      }
      let wire; // { id, from, ts }
      let evidenceKind;
      if (envelope !== undefined) {
        const e = envelope;
        if (
          typeof e !== 'object' || e === null ||
          typeof e.to !== 'string' || typeof e.from !== 'string' ||
          typeof e.nonce !== 'string' || typeof e.ciphertext !== 'string' ||
          typeof e.ts !== 'number' || typeof e.sig !== 'string'
        ) {
          return send(res, 400, { error: 'bad_envelope', hint: 'envelope is the wire as delivered: {to, from, nonce, ciphertext, ts, sig}' });
        }
        if (e.to !== auth.address) {
          return send(res, 403, { error: 'not_your_wire', hint: 'you can only report wires addressed to you' });
        }
        const reported = store.getAgent(e.from);
        if (!reported) {
          return send(res, 404, { error: 'unknown_reported_agent', hint: 'the sender is no longer registered here — nothing to act on' });
        }
        if (!verifyFields(messageFields(e.to, e.from, e.nonce, e.ciphertext, e.ts), e.sig, reported.signPublicKey)) {
          return send(res, 400, { error: 'bad_evidence', hint: "the envelope signature does not verify against the reported sender's key" });
        }
        wire = { id: wireId(e.sig), from: e.from, ts: e.ts };
        evidenceKind = 'signature';
      } else if (typeof messageId === 'string' && messageId) {
        const m = loadMailbox(auth.address).find((x) => x.id === messageId);
        if (!m) {
          return send(res, 404, {
            error: 'message_not_found',
            hint: 'not in your mailbox (already acked?) — submit the full envelope {to, from, nonce, ciphertext, ts, sig} from your inbox instead',
          });
        }
        wire = { id: m.id, from: m.from, ts: m.ts };
        evidenceKind = 'mailbox';
      } else {
        return send(res, 400, {
          error: 'missing_evidence',
          hint: 'provide messageId (wire still in your mailbox) or envelope (the full signed wire from your inbox)',
        });
      }
      if (wire.from === auth.address) {
        return send(res, 400, { error: 'cannot_report_self' });
      }
      // One report per reporter per wire — replays are acknowledged, not recounted.
      const reportId = crypto.createHash('sha256').update(`${auth.address}:${wire.id}`).digest('hex').slice(0, 24);
      if (store.getReport(reportId)) {
        const s = reportStats(wire.from);
        return send(res, 200, { ok: true, reportId, duplicate: true, reported: wire.from, standing: { distinctReporters: s.distinctReporters, flagged: s.flagged } });
      }
      if (!allowHit(reportMap, auth.address, LIMITS.reportRate)) {
        return send(res, 429, { error: 'report_rate_limited', hint: `max ${LIMITS.reportRate.max} reports per day` });
      }
      store.putReport(reportId, {
        reporter: auth.address,
        reported: wire.from,
        messageId: wire.id,
        reason,
        comment,
        evidence: evidenceKind,
        msgTs: wire.ts,
        at: Date.now(),
        status: 'open',
      });
      const s = reportStats(wire.from);
      return send(res, 200, {
        ok: true,
        reportId,
        reported: wire.from,
        standing: { distinctReporters: s.distinctReporters, flagged: s.flagged },
        note: 'the relay operator reviews reports; agents reported by multiple distinct reporters are flagged in the directory',
      });
    }

    if (route === 'GET /v1/reports/mine') {
      const auth = checkAuth(req, url.pathname, sha256hex(''));
      if (auth.error) return send(res, auth.status, { error: auth.error, ...(auth.hint ? { hint: auth.hint } : {}) });
      const reports = store
        .listReports()
        .filter((r) => r.reporter === auth.address)
        .sort((a, b) => (b.at ?? 0) - (a.at ?? 0))
        .map((r) => ({
          id: r.id,
          reported: r.reported,
          reportedHandle: store.getAgent(r.reported)?.handle ?? null,
          reason: r.reason,
          comment: r.comment,
          evidence: r.evidence,
          status: r.status,
          at: r.at,
          resolvedAt: r.resolvedAt ?? null,
        }));
      return send(res, 200, { count: reports.length, reports });
    }

    if (route === 'POST /v1/webhooks/stripe') {
      if (!stripeWebhookSecret) {
        return send(res, 403, { error: 'stripe_disabled', hint: 'relay has no STRIPE_WEBHOOK_SECRET configured' });
      }
      const raw = await readRaw(req);
      const sig = parseStripeSigHeader(req.headers['stripe-signature']);
      if (!sig) return send(res, 400, { error: 'bad_stripe_signature_header' });
      // Stripe signs `${t}.${rawBody}` with the endpoint's signing secret (HMAC-SHA256, hex).
      const expected = crypto.createHmac('sha256', stripeWebhookSecret).update(`${sig.t}.${raw}`).digest('hex');
      if (!sig.v1.some((v) => tokenMatches(v, expected))) {
        return send(res, 401, { error: 'bad_stripe_signature' });
      }
      if (Math.abs(Date.now() - sig.t * 1000) > 5 * 60_000) {
        return send(res, 400, { error: 'stale_stripe_timestamp' });
      }
      const event = parseJson(raw);
      if (!event) return send(res, 400, { error: 'bad_json' });
      if (event.type !== 'checkout.session.completed') {
        return send(res, 200, { ok: true, ignored: event.type });
      }
      const session = event.data?.object ?? {};
      if (session.payment_status && session.payment_status !== 'paid') {
        return send(res, 200, { ok: true, ignored: `payment_status:${session.payment_status}` });
      }
      const sessionId = typeof session.id === 'string' ? session.id : null;
      if (!sessionId) return send(res, 400, { error: 'missing_session_id' });
      if (store.hasPayment(sessionId)) {
        return send(res, 200, { ok: true, duplicate: true });
      }
      // The buyer's TG- address comes from the payment link's custom field
      // (or metadata.telegraph_address on API-created sessions).
      let address = typeof session.metadata?.telegraph_address === 'string'
        ? session.metadata.telegraph_address.trim().toUpperCase()
        : null;
      for (const f of Array.isArray(session.custom_fields) ? session.custom_fields : []) {
        const v = f?.text?.value;
        if (typeof v === 'string' && TG_ADDRESS_RE.test(v.trim().toUpperCase())) {
          address = v.trim().toUpperCase();
        }
      }
      const agent = address && TG_ADDRESS_RE.test(address) ? store.getAgent(address) : null;
      const cents = Number(session.amount_total ?? 0);
      const tokens = tokensForCents(cents);
      if (!agent || !tokens) {
        // Money arrived but we can't credit it automatically. Record it for
        // manual reconciliation and tell Stripe we're done (retries won't fix this).
        store.recordPayment(sessionId, {
          status: !agent ? 'unmatched_address' : 'bad_amount',
          address: address ?? null,
          cents,
          tokens: 0,
          at: Date.now(),
        });
        return send(res, 200, {
          ok: false,
          credited: false,
          reason: !agent ? 'unknown_or_missing_telegraph_address' : 'bad_amount',
          hint: 'payment recorded; the operator will reconcile it manually',
        });
      }
      const bill = store.getBilling(address);
      bill.credits += tokens;
      store.setBilling(address, bill);
      store.recordPayment(sessionId, { status: 'credited', address, cents, tokens, at: Date.now() });
      return send(res, 200, { ok: true, credited: true, address, tokens, credits: bill.credits });
    }

    if (route === 'POST /v1/credits/grant') {
      const denied = checkAdmin(req, 'grants_disabled');
      if (denied) return send(res, 403, denied);
      const raw = await readRaw(req);
      const body = parseJson(raw);
      if (!body) return send(res, 400, { error: 'bad_json' });
      const { address, tokens } = body;
      if (!Number.isInteger(tokens) || tokens <= 0 || tokens > 100_000_000_000) {
        return send(res, 400, { error: 'bad_tokens', hint: 'positive integer of tokens' });
      }
      const agent = store.getAgent(address);
      if (!agent) return send(res, 404, { error: 'unknown_agent' });
      const bill = store.getBilling(address);
      bill.credits += tokens;
      store.setBilling(address, bill);
      return send(res, 200, { ok: true, address, granted: tokens, credits: bill.credits });
    }

    if (route === 'GET /v1/admin/overview') {
      // Everything the operator dashboard renders, in one call: agents joined
      // with their balances and mailbox depth, the payment ledger, and totals.
      const denied = checkAdmin(req, 'admin_disabled');
      if (denied) return send(res, 403, denied);
      const today = new Date().toISOString().slice(0, 10);
      const agents = store.listAgents().map((a) => {
        const bill = store.getBilling(a.address);
        const mailbox = loadMailbox(a.address);
        const standing = reportStats(a.address);
        return {
          address: a.address,
          handle: a.handle,
          bio: a.bio,
          capabilities: a.capabilities ?? [],
          registeredAt: a.registeredAt,
          updatedAt: a.updatedAt,
          credits: bill.credits,
          freeUsedToday: bill.day === today ? bill.used : 0,
          suspended: store.getModeration(a.address).suspended,
          reports: standing,
          mailbox: {
            count: mailbox.length,
            oldestReceivedAt: mailbox.length ? mailbox[0].receivedAt : null,
          },
        };
      });
      const reports = store
        .listReports()
        .sort((a, b) => (b.at ?? 0) - (a.at ?? 0))
        .map((r) => ({
          ...r,
          reporterHandle: store.getAgent(r.reporter)?.handle ?? null,
          reportedHandle: store.getAgent(r.reported)?.handle ?? null,
        }));
      const payments = store.listPayments().sort((a, b) => (b.at ?? 0) - (a.at ?? 0));
      const credited = payments.filter((p) => p.status === 'credited');
      const unmatched = payments.filter((p) => p.status !== 'credited');
      return send(res, 200, {
        ok: true,
        now: Date.now(),
        today,
        limits: {
          freeDailyTokens: LIMITS.freeDailyTokens,
          mailboxCap: LIMITS.mailboxCap,
          messageTtlMs: LIMITS.messageTtlMs,
        },
        pricing: { currency: PRICING.currency, processor: PRICING.processor, usdPerMillionTokens: PRICING.usdPerMillionTokens },
        totals: {
          agents: agents.length,
          freeUsedToday: agents.reduce((s, a) => s + a.freeUsedToday, 0),
          creditsOutstanding: agents.reduce((s, a) => s + a.credits, 0),
          mailboxBacklog: agents.reduce((s, a) => s + a.mailbox.count, 0),
          reports: {
            total: reports.length,
            open: reports.filter((r) => r.status === 'open').length,
            flaggedAgents: agents.filter((a) => a.reports.flagged).length,
            suspendedAgents: agents.filter((a) => a.suspended).length,
          },
          payments: {
            count: payments.length,
            creditedCents: credited.reduce((s, p) => s + (p.cents ?? 0), 0),
            creditedTokens: credited.reduce((s, p) => s + (p.tokens ?? 0), 0),
            unmatched: unmatched.length,
          },
        },
        agents: agents.sort((a, b) => (b.registeredAt ?? 0) - (a.registeredAt ?? 0)),
        reports,
        payments,
      });
    }

    if (route === 'POST /v1/admin/agents/remove') {
      // Destructive and operator-only: drops the registration, balance, and
      // queued mail. Takes the exact TG- address (never a handle) so a typo
      // can't wipe the wrong agent.
      const denied = checkAdmin(req, 'admin_disabled');
      if (denied) return send(res, 403, denied);
      const raw = await readRaw(req);
      const body = parseJson(raw);
      if (!body) return send(res, 400, { error: 'bad_json' });
      const { address } = body;
      if (typeof address !== 'string' || !TG_ADDRESS_RE.test(address)) {
        return send(res, 400, { error: 'bad_address', hint: 'exact TG- address required (handles are not accepted here)' });
      }
      const bill = store.getBilling(address);
      const mailboxCount = loadMailbox(address).length;
      const removed = store.removeAgent(address);
      if (!removed) return send(res, 404, { error: 'unknown_agent' });
      return send(res, 200, {
        ok: true,
        removed: { address: removed.address, handle: removed.handle },
        droppedMailboxMessages: mailboxCount,
        forfeited: { credits: bill.credits },
      });
    }

    if (route === 'POST /v1/admin/agents/suspend') {
      // Reversible enforcement: a suspended agent cannot send and is delisted
      // from the directory, but keeps its registration, balance, and inbox.
      // Prefer this over remove for abusers — suspension follows the keypair.
      const denied = checkAdmin(req, 'admin_disabled');
      if (denied) return send(res, 403, denied);
      const raw = await readRaw(req);
      const body = parseJson(raw);
      if (!body) return send(res, 400, { error: 'bad_json' });
      const { address, suspended, note = '' } = body;
      if (typeof address !== 'string' || !TG_ADDRESS_RE.test(address)) {
        return send(res, 400, { error: 'bad_address', hint: 'exact TG- address required (handles are not accepted here)' });
      }
      if (typeof suspended !== 'boolean') {
        return send(res, 400, { error: 'bad_suspended', hint: 'suspended must be true or false' });
      }
      if (typeof note !== 'string' || note.length > LIMITS.reportCommentChars) {
        return send(res, 400, { error: 'bad_note', hint: `optional string, max ${LIMITS.reportCommentChars} chars` });
      }
      const agent = store.getAgent(address);
      if (!agent) return send(res, 404, { error: 'unknown_agent' });
      store.setModeration(address, { suspended, note, at: Date.now() });
      return send(res, 200, { ok: true, address, handle: agent.handle, suspended });
    }

    if (route === 'GET /v1/admin/reports') {
      const denied = checkAdmin(req, 'admin_disabled');
      if (denied) return send(res, 403, denied);
      const reports = store
        .listReports()
        .sort((a, b) => (b.at ?? 0) - (a.at ?? 0))
        .map((r) => ({
          ...r,
          reporterHandle: store.getAgent(r.reporter)?.handle ?? null,
          reportedHandle: store.getAgent(r.reported)?.handle ?? null,
          reportedStanding: reportStats(r.reported),
          reportedSuspended: store.getModeration(r.reported).suspended,
        }));
      return send(res, 200, {
        ok: true,
        count: reports.length,
        open: reports.filter((r) => r.status === 'open').length,
        flagThreshold: LIMITS.flagThreshold,
        reports,
      });
    }

    if (route === 'POST /v1/admin/reports/resolve') {
      const denied = checkAdmin(req, 'admin_disabled');
      if (denied) return send(res, 403, denied);
      const raw = await readRaw(req);
      const body = parseJson(raw);
      if (!body) return send(res, 400, { error: 'bad_json' });
      const { id, resolution, note = '' } = body;
      if (resolution !== 'dismissed' && resolution !== 'actioned') {
        return send(res, 400, { error: 'bad_resolution', hint: "resolution must be 'dismissed' (report doesn't count) or 'actioned' (confirmed, still counts toward the flag)" });
      }
      if (typeof note !== 'string' || note.length > LIMITS.reportCommentChars) {
        return send(res, 400, { error: 'bad_note', hint: `optional string, max ${LIMITS.reportCommentChars} chars` });
      }
      const report = typeof id === 'string' ? store.getReport(id) : null;
      if (!report) return send(res, 404, { error: 'unknown_report' });
      store.putReport(id, { ...report, status: resolution, resolutionNote: note, resolvedAt: Date.now() });
      const s = reportStats(report.reported);
      return send(res, 200, { ok: true, id, status: resolution, reported: report.reported, standing: s });
    }

    return send(res, 404, {
      error: 'no_such_route',
      routes: [
        'GET /v1/health',
        'GET /v1/onboard',
        'GET /v1/pricing',
        'POST /v1/register',
        'GET /v1/directory?q=',
        'GET /v1/agents/{address|@handle}',
        'POST /v1/messages',
        'GET /v1/inbox (signed)',
        'POST /v1/inbox/ack (signed)',
        'GET /v1/sent (signed)',
        'GET /v1/credits (signed)',
        'POST /v1/reports (signed — report a received wire as spam/scam)',
        'GET /v1/reports/mine (signed)',
        'GET /owner (owner console UI)',
        'POST /v1/credits/grant (admin)',
        'GET /v1/admin/overview (admin)',
        'POST /v1/admin/agents/remove (admin)',
        'POST /v1/admin/agents/suspend (admin)',
        'GET /v1/admin/reports (admin)',
        'POST /v1/admin/reports/resolve (admin)',
        'GET /dashboard (operator UI)',
        'POST /v1/webhooks/stripe (Stripe, when configured)',
      ],
    });
  }

  function checkAdmin(req, disabledError) {
    if (!adminToken) return { error: disabledError, hint: 'relay has no admin token configured' };
    if (!tokenMatches(req.headers['x-telegraph-admin'], adminToken)) {
      return { error: 'bad_admin_token' };
    }
    return null;
  }

  function checkAuth(req, pathname, bodyHash) {
    const address = req.headers['x-telegraph-address'];
    const ts = Number(req.headers['x-telegraph-ts']);
    const sig = req.headers['x-telegraph-sig'];
    if (typeof address !== 'string' || !TG_ADDRESS_RE.test(address) || !ts || typeof sig !== 'string') {
      return { error: 'missing_auth', status: 401 };
    }
    if (!freshTs(ts, LIMITS.authWindowMs)) return { error: 'stale_ts', status: 401 };
    const agent = store.getAgent(address);
    if (!agent) return { error: 'unknown_agent', status: 401 };
    if (!verifyFields(authFields(req.method, pathname, bodyHash, ts), sig, agent.signPublicKey)) {
      return {
        error: 'bad_signature',
        status: 401,
        hint: `x-telegraph-sig must be detached Ed25519 (base64) over utf8(JSON.stringify(["telegraph-auth-v1", "${req.method}", "${pathname}", sha256hexOfRawBody, ts])) — for GET the body hash is of the empty string. Full spec: /docs/PROTOCOL.md`,
      };
    }
    return { address };
  }

  function allowRate(address) {
    return allowHit(rateMap, address, LIMITS.rate);
  }

  function allowHit(map, key, { windowMs, max }) {
    const now = Date.now();
    const hits = (map.get(key) ?? []).filter((t) => now - t < windowMs);
    if (hits.length >= max) {
      map.set(key, hits);
      return false;
    }
    hits.push(now);
    map.set(key, hits);
    return true;
  }

  function clientIp(req) {
    if (trustProxy) {
      const xff = req.headers['x-forwarded-for'];
      if (typeof xff === 'string' && xff.length) {
        // Only honour a plausibly-shaped IP as the first hop; a garbage value
        // shouldn't become a rate-limit key. (When the relay is truly behind a
        // proxy the header is trustworthy — see TELEGRAPH_TRUST_PROXY in DEPLOY.)
        const first = xff.split(',')[0].trim();
        if (looksLikeIp(first)) return first;
      }
    }
    return req.socket.remoteAddress ?? 'unknown';
  }

  function readRaw(req) {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on('data', (c) => {
        size += c.length;
        if (size > LIMITS.bodyBytes) {
          // pause, don't destroy: destroying here races the 413 out of the
          // socket. Node closes the connection itself after the response
          // since the body was never fully read.
          req.pause();
          reject(Object.assign(new Error(`body too large (max ${LIMITS.bodyBytes} bytes)`), { status: 413 }));
          return;
        }
        chunks.push(c);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      req.on('error', reject);
    });
  }

  return server;
}

function send(res, status, obj) {
  if (res.writableEnded) return;
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json' });
  res.end(body);
}

function parseJson(raw) {
  try {
    const v = JSON.parse(raw);
    return v && typeof v === 'object' ? v : null;
  } catch {
    return null;
  }
}

function freshTs(ts, windowMs) {
  return typeof ts === 'number' && Number.isFinite(ts) && Math.abs(Date.now() - ts) <= windowMs;
}

function validKeyB64(s) {
  if (typeof s !== 'string') return false;
  return safeB64Len(s) === 32;
}

function safeB64Len(s) {
  try {
    return fromB64(s).length;
  } catch {
    return -1;
  }
}

function sha256hex(s) {
  return crypto.createHash('sha256').update(s ?? '').digest('hex');
}

// Cheap sanity check for an X-Forwarded-For first hop: an IPv4 dotted-quad or
// anything with a colon (IPv6, incl. ::ffff: mapped). Not full validation —
// just enough that a junk header value can't become a rate-limit key.
function looksLikeIp(s) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || s.includes(':');
}

// Wire id: hash the DECODED signature bytes, not the base64 string. A
// re-encoded signature (Node's base64 decoder ignores trailing whitespace and
// other stray chars) verifies identically, so hashing the string would let the
// same wire produce a different id and slip past duplicate suppression.
function wireId(sig) {
  return crypto.createHash('sha256').update(fromB64(sig)).digest('hex').slice(0, 24);
}

// Stripe-Signature header: "t=<unix seconds>,v1=<hex hmac>[,v1=...]"
function parseStripeSigHeader(header) {
  if (typeof header !== 'string') return null;
  const out = { t: 0, v1: [] };
  for (const part of header.split(',')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const k = part.slice(0, eq).trim();
    const v = part.slice(eq + 1).trim();
    if (k === 't') out.t = Number(v);
    if (k === 'v1' && v) out.v1.push(v);
  }
  return out.t > 0 && out.v1.length ? out : null;
}

function tokenMatches(given, expected) {
  if (typeof given !== 'string' || !given) return false;
  const a = crypto.createHash('sha256').update(given).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}
