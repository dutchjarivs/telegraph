import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer, parseCheckoutUrls } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

// Token estimate: ciphertext = plaintext + 16 bytes; tokens = ceil(plaintextBytes / 4).
// So an 8-char wire costs exactly 2 tokens. Free tier below is tiny on purpose:
// 4 tokens/day = two 8-char wires. Prepaid model: free allowance → credits, no tab.
const ADMIN = 'test-admin-token';
let server;
let base;
let dataDir;
let sender;
let receiver;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-billing-'));
  server = createServer({
    dataDir,
    limits: { freeDailyTokens: 4 },
    adminToken: ADMIN,
    checkoutUrl: 'https://buy.stripe.com/test_link',
    checkoutUrls: { 1: 'https://buy.stripe.com/test_1m', 19: 'https://buy.stripe.com/test_25m' },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  sender = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  receiver = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await sender.register({ handle: 'payer' });
  await receiver.register({ handle: 'payee' });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('pricing endpoint is public, per-token USD via Stripe, and reflects relay limits', async () => {
  const p = await sender.pricing();
  assert.equal(p.currency, 'USD');
  assert.equal(p.processor, 'Stripe');
  assert.equal(p.unit, 'token');
  assert.equal(p.usdPerMillionTokens, 1);
  assert.equal(p.free.tokensPerDay, 4);
  assert.equal(p.bundles.length, 3);
  assert.equal(p.payg, undefined); // no pay-as-you-go tab in the prepaid model
  assert.equal(p.checkout.url, 'https://buy.stripe.com/test_link');
  // Per-bundle links: configured bundles carry their URL, unconfigured ones null.
  assert.equal(p.bundles.find((b) => b.usd === 1).checkoutUrl, 'https://buy.stripe.com/test_1m');
  assert.equal(p.bundles.find((b) => b.usd === 19).checkoutUrl, 'https://buy.stripe.com/test_25m');
  assert.equal(p.bundles.find((b) => b.usd === 499).checkoutUrl, null);
});

test('pricing reports checkout as not-enabled when no link is configured', async () => {
  const bareDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-nocheckout-'));
  const bare = createServer({ dataDir: bareDir, limits: { freeDailyTokens: 4 } });
  await new Promise((resolve) => bare.listen(0, '127.0.0.1', resolve));
  const p = await fetch(`http://127.0.0.1:${bare.address().port}/v1/pricing`).then((r) => r.json());
  assert.equal(p.checkout.url, null);
  assert.match(p.checkout.note, /not enabled/);
  assert.ok(p.bundles.every((b) => b.checkoutUrl === null));
  await new Promise((resolve) => bare.close(resolve));
  fs.rmSync(bareDir, { recursive: true, force: true });
});

test('parseCheckoutUrls reads usd=url pairs and drops malformed entries', () => {
  const m = parseCheckoutUrls('1=https://buy.stripe.com/a, 19=https://buy.stripe.com/b,junk,=https://x,499=http://insecure');
  assert.deepEqual(m, { 1: 'https://buy.stripe.com/a', 19: 'https://buy.stripe.com/b' });
  assert.deepEqual(parseCheckoutUrls(undefined), {});
  assert.deepEqual(parseCheckoutUrls(''), {});
});

test('free tier is metered in tokens; past it a wire is refused (no tab, no debt)', async () => {
  const w1 = await sender.send('@payee', 'wire-001');
  const w2 = await sender.send('@payee', 'wire-002');
  assert.equal(w1.tokens, 2);
  assert.equal(w1.charged, 'free');
  assert.equal(w2.charged, 'free');
  // Free allowance exhausted and no prepaid credits — must be refused outright.
  await assert.rejects(
    () => sender.send('@payee', 'wire-003'),
    (err) => err.status === 402 && /buy more token credits/.test(err.message),
  );
  const c = await sender.credits();
  assert.equal(c.freeRemainingToday, 0);
  assert.equal(c.credits, 0);
  assert.equal(c.owed, undefined); // no tab concept anymore
  assert.equal(c.paygUnlocked, undefined);
});

test('grant rejects a wrong admin token', async () => {
  await assert.rejects(
    () => sender.adminGrant({ address: sender.identity.address, tokens: 5, adminToken: 'wrong' }),
    (err) => err.status === 403,
  );
});

test('grant rejects a malformed address', async () => {
  await assert.rejects(
    () => sender.adminGrant({ address: 'not-a-tg-address', tokens: 5, adminToken: ADMIN }),
    (err) => err.status === 400 && /bad_address/.test(err.message),
  );
  // Handles are also rejected — only exact TG- addresses are accepted.
  await assert.rejects(
    () => sender.adminGrant({ address: '@payee', tokens: 5, adminToken: ADMIN }),
    (err) => err.status === 400 && /bad_address/.test(err.message),
  );
});

test('grant rejects a non-positive token count', async () => {
  await assert.rejects(
    () => sender.adminGrant({ address: sender.identity.address, tokens: 0, adminToken: ADMIN }),
    (err) => err.status === 400,
  );
  await assert.rejects(
    () => sender.adminGrant({ address: sender.identity.address, tokens: -5, adminToken: ADMIN }),
    (err) => err.status === 400,
  );
});

test('prepaid credits are spent after the free allowance', async () => {
  const grant = await sender.adminGrant({ address: sender.identity.address, tokens: 10, adminToken: ADMIN });
  assert.equal(grant.credits, 10);
  const r = await sender.send('@payee', 'wire-003');
  assert.equal(r.charged, 'credit');
  assert.equal(r.tokens, 2);
  const c = await sender.credits();
  assert.equal(c.credits, 8);
});

test('a wire can span free + credits, reported as mixed', async () => {
  // Fresh day would reset free use; here the free allowance is already spent,
  // so grant a fresh identity to exercise the free→credits span cleanly.
  const s2 = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await s2.register({ handle: 'payer2' });
  await s2.adminGrant({ address: s2.identity.address, tokens: 100, adminToken: ADMIN });
  // 24 chars = 6 tokens; free allowance is 4, so 4 free + 2 credits.
  const r = await s2.send('@payee', 'x'.repeat(24));
  assert.equal(r.tokens, 6);
  assert.equal(r.charged, 'mixed');
  assert.deepEqual(r.breakdown, { free: 4, credits: 2 });
  assert.equal(r.credits, 98);
});

test('a wire that outruns free + credits charges nothing (no partial commit)', async () => {
  // sender has 8 credits, 0 free left today; a 40-char wire costs 10 tokens.
  await assert.rejects(
    () => sender.send('@payee', 'x'.repeat(40)),
    (err) => err.status === 402 && /payment_required/.test(err.message),
  );
  const c = await sender.credits();
  assert.equal(c.credits, 8); // untouched
});

test('receiving and acking stay free regardless of balance', async () => {
  const inbox = await receiver.inbox({ ack: true });
  assert.ok(inbox.length >= 4);
  assert.ok(inbox.every((m) => m.verified && typeof m.text === 'string'));
});

test('root path serves JSON to agents', async () => {
  const r = await fetch(base + '/', { headers: { accept: 'application/json' } }).then((r) => r.json());
  assert.equal(r.service, 'telegraph');
  assert.equal(r.pricing, '/v1/pricing');
});

test('root path serves the website to browsers', async () => {
  const res = await fetch(base + '/', { headers: { accept: 'text/html,application/xhtml+xml' } });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /text\/html/);
  const html = await res.text();
  assert.match(html, /Telegraph/);
});
