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
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-owner-'));
  server = createServer({ dataDir, limits: { sentLogCap: 3 }, adminToken: ADMIN });
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

test('sending stores a self-sealed copy the sender can read back', async () => {
  await alice.send('@bob', 'first wire');
  const sent = await alice.sent();
  assert.equal(sent.length, 1);
  assert.equal(sent[0].text, 'first wire');
  assert.equal(sent[0].toHandle, 'bob');
  // The stored copy is ciphertext, not plaintext — the relay stays blind.
  const raw = JSON.parse(fs.readFileSync(path.join(dataDir, 'sent', `${alice.identity.address}.json`), 'utf8'));
  assert.equal(raw.length, 1);
  assert.doesNotMatch(JSON.stringify(raw), /first wire/);
  // And the recipient cannot decrypt the sender's self-copy.
  assert.equal(
    (await (async () => {
      const { decrypt } = await import('../src/crypto.js');
      return decrypt(raw[0].nonce, raw[0].ciphertext, alice.identity.boxPublicKey, bob.identity.boxSecretKey);
    })()),
    null,
  );
});

test('sent log requires signed auth', async () => {
  const res = await fetch(base + '/v1/sent');
  assert.equal(res.status, 401);
});

test('sent log is a ring buffer capped by sentLogCap', async () => {
  await alice.send('@bob', 'wire-two');
  await alice.send('@bob', 'wire-three');
  await alice.send('@bob', 'wire-four'); // cap is 3 — "first wire" rolls off
  const sent = await alice.sent();
  assert.equal(sent.length, 3);
  assert.deepEqual(sent.map((m) => m.text), ['wire-two', 'wire-three', 'wire-four']);
});

test('a wire without sentCopy is still accepted (copies are optional)', async () => {
  const recipient = await bob.lookup('@alice');
  const { encrypt, messageFields, signFields } = await import('../src/crypto.js');
  const { nonce, ciphertext } = encrypt('no copy', recipient.boxPublicKey, bob.identity.boxSecretKey);
  const ts = Date.now();
  const sig = signFields(messageFields(recipient.address, bob.identity.address, nonce, ciphertext, ts), bob.identity.signSecretKey);
  const res = await fetch(base + '/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ to: recipient.address, from: bob.identity.address, nonce, ciphertext, ts, sig }),
  });
  assert.equal(res.status, 200);
  assert.equal((await bob.sent()).length, 0);
});

test('a malformed sentCopy is rejected before anything is charged or stored', async () => {
  const recipient = await bob.lookup('@alice');
  const { encrypt, messageFields, signFields } = await import('../src/crypto.js');
  const { nonce, ciphertext } = encrypt('bad copy', recipient.boxPublicKey, bob.identity.boxSecretKey);
  const ts = Date.now();
  const sig = signFields(messageFields(recipient.address, bob.identity.address, nonce, ciphertext, ts), bob.identity.signSecretKey);
  const res = await fetch(base + '/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ to: recipient.address, from: bob.identity.address, nonce, ciphertext, ts, sig, sentCopy: { nonce: 'short' } }),
  });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'bad_sent_copy');
});

test('removing an agent also drops its sent log', async () => {
  const file = path.join(dataDir, 'sent', `${alice.identity.address}.json`);
  assert.equal(fs.existsSync(file), true);
  const res = await fetch(base + '/v1/admin/agents/remove', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-telegraph-admin': ADMIN },
    body: JSON.stringify({ address: alice.identity.address }),
  });
  assert.equal(res.status, 200);
  assert.equal(fs.existsSync(file), false);
});

test('owner console and nacl vendor file are served', async () => {
  const page = await fetch(base + '/owner');
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-type'), /text\/html/);
  assert.match(await page.text(), /Owner console/);
  const nacljs = await fetch(base + '/vendor/nacl-fast.min.js');
  assert.equal(nacljs.status, 200);
  assert.match(nacljs.headers.get('content-type'), /javascript/);
});

test('owner console ships the abuse-report UI', async () => {
  const html = await (await fetch(base + '/owner')).text();
  assert.match(html, /id="reportModal"/); // proper modal, not prompt() dialogs
  assert.match(html, /\/v1\/reports\/mine/); // filed-reports section is wired to the API
  assert.match(html, /Reports you've filed/);
  assert.match(html, /suspended-badge/); // threads label suspended senders
});

test('onboarding wizard page is served', async () => {
  const page = await fetch(base + '/onboard');
  assert.equal(page.status, 200);
  assert.match(page.headers.get('content-type'), /text\/html/);
  const html = await page.text();
  assert.match(html, /Onboarding/);
  assert.match(html, /Generate.*keypair/i);
  assert.match(html, /Register.*handle/i);
  assert.match(html, /test wire/i);
  assert.match(html, /tweetnacl/); // loads NaCl for client-side crypto
});
