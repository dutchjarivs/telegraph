import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

const ADMIN = 'test-admin-token';
let server;
let base;
let dataDir;
let alice;
let bob;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-regress-'));
  // bodyBytes stays large enough for a full-size wire (~16KB b64 + envelope);
  // the 413 test posts to /v1/register instead, capped well below that.
  server = createServer({ dataDir, limits: { mailboxCap: 2, bodyBytes: 40_000, freeDailyTokens: 10_000 }, adminToken: ADMIN });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  alice = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  bob = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await alice.register({ handle: 'alice' });
  await bob.register({ handle: 'bob' });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('wires stay decryptable and verified after the sender is removed', async () => {
  await alice.send('@bob', 'outlive me');
  const gone = await fetch(base + '/v1/admin/agents/remove', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-telegraph-admin': ADMIN },
    body: JSON.stringify({ address: alice.identity.address }),
  });
  assert.equal(gone.status, 200);
  // The live record is gone, but the delivery-time snapshot still lets the
  // recipient verify the sender and decrypt the wire.
  const inbox = await bob.inbox();
  const wire = inbox.find((m) => m.from === alice.identity.address);
  assert.equal(wire.text, 'outlive me');
  assert.equal(wire.verified, true);
  assert.equal(wire.fromHandle, 'alice');
});

test('sent log keeps the recipient handle after the recipient is removed', async () => {
  // alice was removed above; bob's sends should still label her thread.
  await alice.register({ handle: 'alice2' }); // same keys, back under a new handle
  await bob.send('@alice2', 'label me');
  await fetch(base + '/v1/admin/agents/remove', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-telegraph-admin': ADMIN },
    body: JSON.stringify({ address: alice.identity.address }),
  });
  const sent = await bob.sent();
  const entry = sent.find((m) => m.text === 'label me');
  assert.equal(entry.toHandle, 'alice2');
});

test('resending a delivered wire into a full mailbox is a duplicate, not a 507', async () => {
  await alice.register({ handle: 'alice3' });
  const { encrypt, messageFields, signFields } = await import('../src/crypto.js');
  const recipient = await alice.lookup('@bob');
  const sendRaw = async (text, reuse) => {
    const enc = reuse ?? encrypt(text, recipient.boxPublicKey, alice.identity.boxSecretKey);
    const ts = reuse?.ts ?? Date.now();
    const sig = signFields(messageFields(recipient.address, alice.identity.address, enc.nonce, enc.ciphertext, ts), alice.identity.signSecretKey);
    const res = await fetch(base + '/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ to: recipient.address, from: alice.identity.address, nonce: enc.nonce, ciphertext: enc.ciphertext, ts, sig }),
    });
    return { status: res.status, body: await res.json(), enc: { ...enc, ts } };
  };
  const first = await sendRaw('fill-1'); // mailbox already has 1 from earlier test → now at cap 2
  assert.equal(first.status, 200);
  const dup = await sendRaw(null, first.enc); // exact same envelope, box now full
  assert.equal(dup.status, 200);
  assert.equal(dup.body.duplicate, true);
  const overflow = await sendRaw('fill-2'); // a NEW wire must still bounce
  assert.equal(overflow.status, 507);
});

test('an oversized body gets 413, not 500', async () => {
  const res = await fetch(base + '/v1/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: 'x'.repeat(60_000), // bodyBytes limit is 40,000 in this harness
  });
  assert.equal(res.status, 413);
  assert.equal((await res.json()).error, 'too_large');
});

test('worst-case multibyte wire at the char cap still fits the relay ciphertext cap', async () => {
  // 4000 UTF-16 units of 3-byte chars = 12KB UTF-8 — the absolute worst case
  // the client can produce. It must be accepted, not bounce off the 16KB cap.
  const r = await bob.send('@alice3', 'あ'.repeat(4000));
  assert.equal(typeof r.id, 'string');
});

test('html pages are served with no-store so UI fixes always arrive', async () => {
  for (const p of ['/owner', '/dashboard']) {
    const res = await fetch(base + p);
    assert.equal(res.headers.get('cache-control'), 'no-store', p);
  }
  const site = await fetch(base + '/', { headers: { accept: 'text/html' } });
  assert.equal(site.headers.get('cache-control'), 'no-store', '/');
});

test('landing page has the owner login button in the topbar', async () => {
  const res = await fetch(base + '/', { headers: { accept: 'text/html' } });
  const html = await res.text();
  assert.match(html, /class="owner-login" href="\/owner"/);
});
