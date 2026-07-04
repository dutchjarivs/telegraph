import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

// Token estimate: ciphertext = plaintext + 16 bytes; tokens = ceil(plaintextBytes / 4).
// So an 8-char wire costs exactly 2 tokens. Limits below are tiny on purpose:
// free tier = 4 tokens/day (two 8-char wires), payg tab = 3 tokens.
const ADMIN = 'test-admin-token';
let server;
let base;
let dataDir;
let sender;
let receiver;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-billing-'));
  server = createServer({ dataDir, limits: { freeDailyTokens: 4, paygCapTokens: 3 }, adminToken: ADMIN });
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

test('pricing endpoint is public, per-token, and reflects relay limits', async () => {
  const p = await sender.pricing();
  assert.equal(p.currency, 'USDC');
  assert.equal(p.unit, 'token');
  assert.equal(p.usdPerMillionTokens, 1);
  assert.equal(p.free.tokensPerDay, 4);
  assert.equal(p.payg.tabTokens, 3);
  assert.equal(p.bundles.length, 3);
});

test('free tier is metered in tokens; the payg tab is locked before any payment', async () => {
  const w1 = await sender.send('@payee', 'wire-001');
  const w2 = await sender.send('@payee', 'wire-002');
  assert.equal(w1.tokens, 2);
  assert.equal(w1.charged, 'free');
  assert.equal(w2.charged, 'free');
  // Free allowance exhausted; the tab must NOT open for a never-paid identity.
  await assert.rejects(
    () => sender.send('@payee', 'wire-003'),
    (err) => err.status === 402 && /first paid top-up/.test(err.message),
  );
  const c = await sender.credits();
  assert.equal(c.freeRemainingToday, 0);
  assert.equal(c.owed, 0); // nothing went on the locked tab
  assert.equal(c.paygUnlocked, false);
  assert.equal(c.paygRemaining, 0);
});

test('grant and settle reject a wrong admin token', async () => {
  await assert.rejects(
    () => sender.adminGrant({ address: sender.identity.address, tokens: 5, adminToken: 'wrong' }),
    (err) => err.status === 403,
  );
  await assert.rejects(
    () => sender.adminSettle({ address: sender.identity.address, tokens: 1, adminToken: 'wrong' }),
    (err) => err.status === 403,
  );
});

test('a first paid grant adds credits and unlocks the payg tab', async () => {
  const grant = await sender.adminGrant({ address: sender.identity.address, tokens: 10, adminToken: ADMIN });
  assert.equal(grant.credits, 10);
  const r = await sender.send('@payee', 'wire-003');
  assert.equal(r.charged, 'credit');
  assert.equal(r.tokens, 2);
  const c = await sender.credits();
  assert.equal(c.credits, 8);
  assert.equal(c.paygUnlocked, true);
  assert.equal(c.paygRemaining, 3);
});

test('a wire can span tiers: credits then tab, reported as mixed', async () => {
  // 40 chars = 10 tokens; sender has 8 credits + empty 3-token tab.
  const r = await sender.send('@payee', 'x'.repeat(40));
  assert.equal(r.tokens, 10);
  assert.equal(r.charged, 'mixed');
  assert.deepEqual(r.breakdown, { free: 0, credits: 8, payg: 2 });
  assert.equal(r.credits, 0);
  assert.equal(r.owed, 2);
});

test('a rejected wire charges nothing (no partial commit)', async () => {
  // Tab has 1 token left but the wire costs 2 — must be rejected, not partially charged.
  await assert.rejects(
    () => sender.send('@payee', 'wire-004'),
    (err) => err.status === 402 && /payment_required/.test(err.message),
  );
  const c = await sender.credits();
  assert.equal(c.credits, 0);
  assert.equal(c.owed, 2);
  assert.equal(c.paygRemaining, 1);
});

test('settle clears the pay-as-you-go tab (floor at zero)', async () => {
  const s1 = await sender.adminSettle({ address: sender.identity.address, tokens: 1, adminToken: ADMIN });
  assert.equal(s1.settled, 1);
  assert.equal(s1.owed, 1);
  const s2 = await sender.adminSettle({ address: sender.identity.address, tokens: 10, adminToken: ADMIN });
  assert.equal(s2.settled, 1);
  assert.equal(s2.owed, 0);
  const c = await sender.credits();
  assert.equal(c.owed, 0);
  assert.equal(c.paygRemaining, 3);
});

test('receiving and acking stay free regardless of balance', async () => {
  const inbox = await receiver.inbox({ ack: true });
  assert.equal(inbox.length, 4);
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
