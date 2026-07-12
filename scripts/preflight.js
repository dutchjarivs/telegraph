#!/usr/bin/env node
// Deploy preflight: proves this box can actually run the relay before you
// point traffic at it. Boots a throwaway relay on an ephemeral port and runs a
// real wire through it (keygen → register → send → read → ack), then reviews
// the environment the service will start with. Exit 0 = go, 1 = fix first.
//
//   npm run preflight        (run from the app directory, next to .env if any)
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

const checks = [];
const add = (name, level, detail) => checks.push({ name, level, detail }); // level: ok | warn | fail

// The systemd unit loads .env (DEPLOY.md step 3); mirror that so preflight
// reviews what the service will actually see. Real env vars win.
const env = { ...readDotEnv(path.resolve('.env')), ...process.env };

// --- Node version ---------------------------------------------------------
const major = Number(process.versions.node.split('.')[0]);
add('node', major >= 18 ? 'ok' : 'fail',
  `node ${process.versions.node}${major >= 18 ? '' : ' — the relay needs Node 18+ (global fetch)'}`);

// --- Smoke test: a real wire through a throwaway relay ---------------------
let smokeDir;
try {
  smokeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-preflight-'));
  const server = createServer({ dataDir: smokeDir });
  await new Promise((resolve, reject) => {
    server.on('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  try {
    const base = `http://127.0.0.1:${server.address().port}`;
    const alice = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
    const bob = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
    await alice.register({ handle: 'preflight-alice' });
    await bob.register({ handle: 'preflight-bob' });
    await alice.send('@preflight-bob', 'preflight wire — if you can read this, the relay works');
    const inbox = await bob.inbox();
    if (inbox.length !== 1 || !inbox[0].verified || !inbox[0].text?.includes('preflight wire')) {
      throw new Error('wire arrived garbled or unverified');
    }
    await bob.ack([inbox[0].id]);
    add('smoke', 'ok', 'keygen → register → send → read (decrypted, verified) → ack, all on a throwaway relay');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
} catch (err) {
  add('smoke', 'fail', `end-to-end wire failed on this box: ${err.message}`);
} finally {
  if (smokeDir) fs.rmSync(smokeDir, { recursive: true, force: true });
}

// --- Data dir writable ------------------------------------------------------
const dataDir = path.resolve('./data');
try {
  fs.mkdirSync(dataDir, { recursive: true });
  const probe = path.join(dataDir, '.preflight-probe');
  fs.writeFileSync(probe, 'ok');
  fs.rmSync(probe);
  add('data-dir', 'ok', `${dataDir} is writable`);
} catch (err) {
  add('data-dir', 'fail', `${dataDir} not writable by this user: ${err.message}`);
}

// --- Environment review -----------------------------------------------------
const adminToken = env.TELEGRAPH_ADMIN_TOKEN ?? '';
if (!adminToken) {
  add('admin-token', 'warn', 'TELEGRAPH_ADMIN_TOKEN unset — every operator endpoint (grant, suspend, reports, overview) will 403');
} else if (adminToken.length < 32) {
  add('admin-token', 'fail', `TELEGRAPH_ADMIN_TOKEN is only ${adminToken.length} chars — use a long random string (openssl rand -hex 32)`);
} else {
  add('admin-token', 'ok', `set (${adminToken.length} chars)`);
}

const whsec = env.STRIPE_WEBHOOK_SECRET ?? '';
if (!whsec) {
  add('stripe-webhook', 'warn', 'STRIPE_WEBHOOK_SECRET unset — card checkout stays disabled (fine until Stripe is ready)');
} else if (!whsec.startsWith('whsec_')) {
  add('stripe-webhook', 'fail', 'STRIPE_WEBHOOK_SECRET does not start with whsec_ — that is not an endpoint signing secret');
} else {
  add('stripe-webhook', 'ok', 'set');
}

const checkout = env.TELEGRAPH_CHECKOUT_URL ?? '';
if (!checkout) {
  add('checkout-url', 'warn', 'TELEGRAPH_CHECKOUT_URL unset — /v1/pricing will report checkout not-enabled');
} else if (!/^https:\/\//.test(checkout)) {
  add('checkout-url', 'fail', 'TELEGRAPH_CHECKOUT_URL must be an https:// Stripe Payment Link');
} else {
  add('checkout-url', 'ok', checkout);
}

const bundleUrls = env.TELEGRAPH_CHECKOUT_URLS ?? '';
if (bundleUrls) {
  const pairs = bundleUrls.split(',').filter((p) => p.trim());
  const good = pairs.filter((p) => {
    const i = p.indexOf('=');
    return i > 0 && Number.isFinite(Number(p.slice(0, i).trim())) && /^https:\/\//.test(p.slice(i + 1).trim());
  });
  if (good.length === pairs.length) {
    add('checkout-urls', 'ok', `${good.length} per-bundle link(s)`);
  } else {
    add('checkout-urls', 'fail', `TELEGRAPH_CHECKOUT_URLS has ${pairs.length - good.length} malformed pair(s) — expected "usd=https://..." comma-separated`);
  }
}

if (whsec && !checkout) {
  add('stripe-pairing', 'warn', 'webhook secret set but no checkout URL — agents get credited if they find the link, but pricing won\'t show it');
}

add('trust-proxy', 'ok', env.TELEGRAPH_TRUST_PROXY === '1'
  ? 'TELEGRAPH_TRUST_PROXY=1 — only correct behind a reverse proxy you control (Caddy/cloudflared); remove it on a directly exposed relay'
  : 'unset — client IPs are taken from the socket (correct for a directly exposed relay; set to 1 behind Caddy)');

const ttl = env.TELEGRAPH_MESSAGE_TTL_DAYS;
if (ttl !== undefined && ttl !== '') {
  const n = Number(ttl);
  if (Number.isFinite(n) && n > 0) add('message-ttl', 'ok', `unfetched wires expire after ${n} day(s)`);
  else add('message-ttl', 'fail', `TELEGRAPH_MESSAGE_TTL_DAYS=${ttl} is not a positive number`);
}

// --- Port -------------------------------------------------------------------
const port = Number(env.TELEGRAPH_PORT ?? 7787);
const portDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-port-'));
await new Promise((resolve) => {
  const probe = createServer({ dataDir: portDir });
  probe.once('error', (err) => {
    add('port', 'warn', err.code === 'EADDRINUSE'
      ? `port ${port} already in use — an existing relay? (fine if this is a redeploy)`
      : `port ${port} probe failed: ${err.message}`);
    resolve();
  });
  probe.listen(port, '127.0.0.1', () => {
    add('port', 'ok', `port ${port} is free`);
    probe.close(resolve);
  });
});
fs.rmSync(portDir, { recursive: true, force: true });

// --- Verdict ----------------------------------------------------------------
const fails = checks.filter((c) => c.level === 'fail');
const warns = checks.filter((c) => c.level === 'warn');
console.log(JSON.stringify({
  ok: fails.length === 0,
  summary: `${checks.length} checks: ${checks.length - fails.length - warns.length} ok, ${warns.length} warnings, ${fails.length} failures`,
  checks,
}, null, 2));
// exitCode, not exit(): a hard exit with fetch keep-alive sockets still open
// crashes Node on Windows (STATUS_STACK_BUFFER_OVERRUN).
process.exitCode = fails.length === 0 ? 0 : 1;

function readDotEnv(file) {
  if (!fs.existsSync(file)) return {};
  const out = {};
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = /^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return out;
}
