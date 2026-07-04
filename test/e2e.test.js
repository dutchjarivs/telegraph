import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';
import * as tg from '../src/crypto.js';

let server;
let base;
let dataDir;
let alice;
let bob;
let mallory; // registered agent used for negative tests

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-test-'));
  server = createServer({ dataDir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  alice = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  bob = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  mallory = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('health check', async () => {
  const r = await fetch(`${base}/v1/health`).then((r) => r.json());
  assert.equal(r.ok, true);
  assert.equal(r.service, 'telegraph');
});

test('agents register and get TG- addresses', async () => {
  const a = await alice.register({ handle: 'alice', bio: 'test agent A', capabilities: ['research', 'trading'] });
  const b = await bob.register({ handle: 'bob', bio: 'test agent B', capabilities: ['support'] });
  await mallory.register({ handle: 'mallory', bio: 'up to no good' });
  assert.match(a.address, /^TG-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$/);
  assert.equal(a.address, alice.identity.address);
  assert.equal(b.handle, 'bob');
});

test('handle collision from a different key is rejected', async () => {
  const impostor = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await assert.rejects(() => impostor.register({ handle: 'alice' }), (err) => err.status === 409);
});

test('re-registration by the same key updates the record', async () => {
  const r = await alice.register({ handle: 'alice', bio: 'updated bio', capabilities: ['research'] });
  assert.equal(r.ok, true);
  const rec = await alice.lookup('@alice');
  assert.equal(rec.bio, 'updated bio');
  assert.equal(rec.verified, true);
});

test('directory lists agents, search filters, records verify client-side', async () => {
  const all = await alice.directory();
  assert.equal(all.count, 3);
  assert.ok(all.agents.every((a) => a.verified === true));
  const hits = await alice.directory('support');
  assert.equal(hits.count, 1);
  assert.equal(hits.agents[0].handle, 'bob');
});

test('alice wires bob; bob reads it decrypted and verified', async () => {
  const sent = await alice.send('@bob', 'Meet me at the AgentMart checkout. Bring USDC.');
  assert.ok(sent.id);
  const inbox = await bob.inbox();
  assert.equal(inbox.length, 1);
  assert.equal(inbox[0].text, 'Meet me at the AgentMart checkout. Bring USDC.');
  assert.equal(inbox[0].fromHandle, 'alice');
  assert.equal(inbox[0].from, alice.identity.address);
  assert.equal(inbox[0].verified, true);
});

test('relay stores only ciphertext — plaintext never touches disk', () => {
  const mailboxDir = path.join(dataDir, 'mailboxes');
  const files = fs.readdirSync(mailboxDir).map((f) => fs.readFileSync(path.join(mailboxDir, f), 'utf8'));
  const everything = files.join('') + fs.readFileSync(path.join(dataDir, 'agents.json'), 'utf8');
  assert.ok(!everything.includes('AgentMart checkout'));
});

test('duplicate envelope is deduped', async () => {
  // Re-send the exact same signed envelope: server answers ok but stores once.
  const recipient = await alice.lookup('@bob');
  const { nonce, ciphertext } = tg.encrypt('dup test', recipient.boxPublicKey, alice.identity.boxSecretKey);
  const ts = Date.now();
  const sig = tg.signFields(tg.messageFields(recipient.address, alice.identity.address, nonce, ciphertext, ts), alice.identity.signSecretKey);
  const envelope = { to: recipient.address, from: alice.identity.address, nonce, ciphertext, ts, sig };
  const post = () =>
    fetch(`${base}/v1/messages`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(envelope),
    }).then((r) => r.json());
  const first = await post();
  const second = await post();
  assert.equal(first.ok, true);
  assert.equal(second.duplicate, true);
  const inbox = await bob.inbox();
  assert.equal(inbox.filter((m) => m.text === 'dup test').length, 1);
});

test('forged sender signature is rejected', async () => {
  const recipient = await mallory.lookup('@bob');
  const { nonce, ciphertext } = tg.encrypt('forged', recipient.boxPublicKey, mallory.identity.boxSecretKey);
  const ts = Date.now();
  // Mallory claims to be alice but signs with her own key.
  const sig = tg.signFields(tg.messageFields(recipient.address, alice.identity.address, nonce, ciphertext, ts), mallory.identity.signSecretKey);
  const res = await fetch(`${base}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ to: recipient.address, from: alice.identity.address, nonce, ciphertext, ts, sig }),
  });
  assert.equal(res.status, 401);
});

test('unregistered sender is rejected', async () => {
  const ghost = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  const recipient = await ghost.lookup('@bob');
  const { nonce, ciphertext } = tg.encrypt('boo', recipient.boxPublicKey, ghost.identity.boxSecretKey);
  const ts = Date.now();
  const sig = tg.signFields(tg.messageFields(recipient.address, ghost.identity.address, nonce, ciphertext, ts), ghost.identity.signSecretKey);
  const res = await fetch(`${base}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ to: recipient.address, from: ghost.identity.address, nonce, ciphertext, ts, sig }),
  });
  assert.equal(res.status, 401);
});

test('a third party cannot decrypt an intercepted wire', async () => {
  const recipient = await alice.lookup('@bob');
  const { nonce, ciphertext } = tg.encrypt('secret plans', recipient.boxPublicKey, alice.identity.boxSecretKey);
  const stolen = tg.decrypt(nonce, ciphertext, alice.identity.boxPublicKey, mallory.identity.boxSecretKey);
  assert.equal(stolen, null);
  const legit = tg.decrypt(nonce, ciphertext, alice.identity.boxPublicKey, bob.identity.boxSecretKey);
  assert.equal(legit, 'secret plans');
});

test('tampered ciphertext fails authenticated decryption', async () => {
  const recipient = await alice.lookup('@bob');
  const { nonce, ciphertext } = tg.encrypt('do not touch', recipient.boxPublicKey, alice.identity.boxSecretKey);
  const bytes = tg.fromB64(ciphertext);
  bytes[bytes.length - 1] ^= 0xff;
  const tampered = tg.toB64(bytes);
  assert.equal(tg.decrypt(nonce, tampered, alice.identity.boxPublicKey, bob.identity.boxSecretKey), null);
});

test('inbox auth: stale timestamp is rejected', async () => {
  const ts = Date.now() - 10 * 60_000;
  const bodyHash = await sha256hex('');
  const sig = tg.signFields(tg.authFields('GET', '/v1/inbox', bodyHash, ts), bob.identity.signSecretKey);
  const res = await fetch(`${base}/v1/inbox`, {
    headers: {
      'x-telegraph-address': bob.identity.address,
      'x-telegraph-ts': String(ts),
      'x-telegraph-sig': sig,
    },
  });
  assert.equal(res.status, 401);
});

test('inbox auth: another agent cannot read your mail', async () => {
  const ts = Date.now();
  const bodyHash = await sha256hex('');
  // Mallory signs with her key but claims bob's address.
  const sig = tg.signFields(tg.authFields('GET', '/v1/inbox', bodyHash, ts), mallory.identity.signSecretKey);
  const res = await fetch(`${base}/v1/inbox`, {
    headers: {
      'x-telegraph-address': bob.identity.address,
      'x-telegraph-ts': String(ts),
      'x-telegraph-sig': sig,
    },
  });
  assert.equal(res.status, 401);
});

test('ack clears the mailbox', async () => {
  const before = await bob.inbox();
  assert.ok(before.length >= 1);
  await bob.ack(before.map((m) => m.id));
  const after = await bob.inbox();
  assert.equal(after.length, 0);
});

test('oversized wire is rejected client-side', async () => {
  await assert.rejects(() => alice.send('@bob', 'x'.repeat(4001)), /max 4000 chars/);
});

async function sha256hex(s) {
  const { createHash } = await import('node:crypto');
  return createHash('sha256').update(s).digest('hex');
}
