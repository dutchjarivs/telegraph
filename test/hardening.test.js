// Regression tests for the security review fixes (2026-07-06):
//  1. prototype-chain keys can't bypass address/existence checks
//  2. duplicate suppression survives signature re-encoding
//  3. malformed input returns a clean 4xx, not a 500 with internal detail
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';
import { messageFields, signFields, encrypt } from '../src/crypto.js';

let server;
let base;
let dataDir;
let alice;
let bob;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-hardening-'));
  server = createServer({ dataDir, limits: { freeDailyTokens: 100_000 } });
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

const post = (p, body) =>
  fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

test('a wire addressed to a prototype key is rejected, not delivered', async () => {
  for (const target of ['__proto__', 'constructor', 'toString']) {
    const res = await post('/v1/messages', {
      to: target,
      from: alice.identity.address,
      nonce: 'x',
      ciphertext: 'x',
      ts: Date.now(),
      sig: 'x',
    });
    assert.equal(res.status, 400, `to=${target} should be 400`);
    assert.equal((await res.json()).error, 'bad_address');
  }
  // and none of those turned into junk mailbox files
  const files = fs.readdirSync(path.join(dataDir, 'mailboxes'));
  for (const junk of ['proto.json', 'constructor.json', 'toString.json']) {
    assert.ok(!files.includes(junk), `unexpected mailbox file ${junk}`);
  }
});

test('a prototype key in the auth address header does not bypass unknown_agent', async () => {
  const res = await fetch(base + '/v1/inbox', {
    headers: { 'x-telegraph-address': '__proto__', 'x-telegraph-ts': String(Date.now()), 'x-telegraph-sig': 'AAAA' },
  });
  assert.equal(res.status, 401);
});

test('duplicate suppression survives a re-encoded signature', async () => {
  const mts = Date.now();
  const { nonce, ciphertext } = encrypt('spam', bob.identity.boxPublicKey, alice.identity.boxSecretKey);
  const sig = signFields(
    messageFields(bob.identity.address, alice.identity.address, nonce, ciphertext, mts),
    alice.identity.signSecretKey,
  );
  const wire = { to: bob.identity.address, from: alice.identity.address, nonce, ciphertext, ts: mts, sig };

  const first = await (await post('/v1/messages', wire)).json();
  assert.equal(first.duplicate ?? false, false);

  // Same signature bytes, different base64 string (trailing space the decoder
  // ignores). Must be recognised as the same wire, not delivered twice.
  const second = await (await post('/v1/messages', { ...wire, sig: sig + ' ' })).json();
  assert.equal(second.duplicate, true);
  assert.equal(second.id, first.id);

  const inbox = await bob.inbox();
  const copies = inbox.filter((m) => m.id === first.id);
  assert.equal(copies.length, 1, 'exactly one copy should land in the mailbox');
});

test('malformed url encoding returns a clean 400, not a 500 with internal detail', async () => {
  const res = await fetch(base + '/v1/agents/%ZZ');
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, 'bad_request');
  assert.ok(!('detail' in body), 'must not leak internal error detail');
});

test('a valid-format but unregistered address still reads as unknown, not bad_address', async () => {
  // format check must not swallow the real "unknown sender" signal
  const { nonce, ciphertext } = encrypt('hi', bob.identity.boxPublicKey, alice.identity.boxSecretKey);
  const res = await post('/v1/messages', {
    to: bob.identity.address,
    from: 'TG-AAAA-BBBB-CCCC-DDDD', // well-formed, never registered
    nonce,
    ciphertext,
    ts: Date.now(),
    sig: 'AAAA',
  });
  assert.equal(res.status, 401);
  assert.equal((await res.json()).error, 'unknown_sender');
});
