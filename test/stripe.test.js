import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

const WHSEC = 'whsec_test_secret_for_telegraph';
let server;
let base;
let dataDir;
let buyer;

function stripeEvent(sessionOverrides = {}) {
  return {
    id: 'evt_test_1',
    type: 'checkout.session.completed',
    data: {
      object: {
        id: 'cs_test_default',
        payment_status: 'paid',
        amount_total: 100, // $1 -> 1M tokens
        custom_fields: [
          { key: 'telegraph_address', text: { value: buyer.identity.address } },
        ],
        ...sessionOverrides,
      },
    },
  };
}

function post(body, { secret = WHSEC, tsOffsetSec = 0, badSig = false } = {}) {
  const raw = JSON.stringify(body);
  const t = Math.floor(Date.now() / 1000) + tsOffsetSec;
  const sig = badSig
    ? '0'.repeat(64)
    : crypto.createHmac('sha256', secret).update(`${t}.${raw}`).digest('hex');
  return fetch(base + '/v1/webhooks/stripe', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'stripe-signature': `t=${t},v1=${sig}` },
    body: raw,
  });
}

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-stripe-'));
  server = createServer({ dataDir, stripeWebhookSecret: WHSEC });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  buyer = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await buyer.register({ handle: 'buyer' });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('webhook is disabled with 403 when no secret is configured', async () => {
  const bare = createServer({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-nostripe-')), stripeWebhookSecret: undefined });
  await new Promise((resolve) => bare.listen(0, '127.0.0.1', resolve));
  const r = await fetch(`http://127.0.0.1:${bare.address().port}/v1/webhooks/stripe`, { method: 'POST', body: '{}' });
  assert.equal(r.status, 403);
  await new Promise((resolve) => bare.close(resolve));
});

test('a paid checkout session credits the TG address from the custom field', async () => {
  const r = await post(stripeEvent({ id: 'cs_test_a' }));
  assert.equal(r.status, 200);
  const j = await r.json();
  assert.equal(j.credited, true);
  assert.equal(j.tokens, 1_000_000);
  const c = await buyer.credits();
  assert.equal(c.credits, 1_000_000);
  assert.equal(c.paygUnlocked, true); // a card payment unlocks the tab like any grant
});

test('bundle amounts map to discounted token counts', async () => {
  const r = await post(stripeEvent({ id: 'cs_test_bundle', amount_total: 1900 }));
  const j = await r.json();
  assert.equal(j.tokens, 25_000_000); // $19 bundle, not 19M base-rate tokens
});

test('duplicate delivery of the same session is not double-credited', async () => {
  const before = (await buyer.credits()).credits;
  const r = await post(stripeEvent({ id: 'cs_test_a' })); // same id as earlier test
  const j = await r.json();
  assert.equal(j.duplicate, true);
  assert.equal((await buyer.credits()).credits, before);
});

test('a forged signature is rejected and credits nothing', async () => {
  const before = (await buyer.credits()).credits;
  const r = await post(stripeEvent({ id: 'cs_test_forged' }), { badSig: true });
  assert.equal(r.status, 401);
  assert.equal((await buyer.credits()).credits, before);
});

test('a stale timestamp is rejected (replay protection)', async () => {
  const r = await post(stripeEvent({ id: 'cs_test_stale' }), { tsOffsetSec: -3600 });
  assert.equal(r.status, 400);
});

test('a payment with no valid TG address is recorded, not credited, and not retried', async () => {
  const r = await post(stripeEvent({ id: 'cs_test_lost', custom_fields: [{ key: 'telegraph_address', text: { value: 'not-an-address' } }] }));
  assert.equal(r.status, 200); // 200 so Stripe stops retrying — a retry can't fix a bad address
  const j = await r.json();
  assert.equal(j.credited, false);
  assert.match(j.reason, /address/);
  const payments = JSON.parse(fs.readFileSync(path.join(dataDir, 'payments.json'), 'utf8'));
  assert.equal(payments.cs_test_lost.status, 'unmatched_address');
});

test('non-checkout events are acknowledged and ignored', async () => {
  const r = await post({ id: 'evt_other', type: 'invoice.paid', data: { object: {} } });
  const j = await r.json();
  assert.equal(j.ignored, 'invoice.paid');
});
