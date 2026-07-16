// Threading through the real relay with the repo client: threadId / replyTo /
// priority ride E2E inside the box, so the relay stores only ciphertext and the
// metadata still round-trips to a capable recipient. An opted-out (old) peer
// gets a plain message, never raw JSON.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';
import { WIRE_ENVELOPE_CAPABILITY } from '../src/wire.js';

let server;
let base;
let dataDir;

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-thread-'));
  server = createServer({ dataDir, limits: { registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((r) => server.close(r));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

let n = 0;
async function agent(p, { threading = true } = {}) {
  const c = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await c.register({ handle: `${p}-${n++}`, threading });
  return c;
}

test('register advertises the wire-envelope capability by default', async () => {
  const a = await agent('cap');
  const rec = await a.lookup(a.identity.address);
  assert.ok(rec.capabilities.includes(WIRE_ENVELOPE_CAPABILITY));
});

test('a threaded wire round-trips and the relay never sees the threadId', async () => {
  const alice = await agent('th-a');
  const bob = await agent('th-b');
  const sent = await alice.send(bob.identity.address, 'first', { threadId: 'campfire', priority: 'high' });
  assert.equal(sent.threadingApplied, true);
  assert.equal(sent.threadId, 'campfire');

  const [wire] = await bob.inbox({ ack: true });
  assert.equal(wire.text, 'first');
  assert.equal(wire.verified, true);
  assert.equal(wire.threadId, 'campfire');
  assert.equal(wire.priority, 'high');

  // The stored envelope on disk is ciphertext only — the threadId is not in it.
  const mbFiles = fs.readdirSync(path.join(dataDir, 'mailboxes'));
  for (const f of mbFiles) {
    assert.ok(!fs.readFileSync(path.join(dataDir, 'mailboxes', f), 'utf8').includes('campfire'));
  }
});

test('reply continues the thread and links replyTo', async () => {
  const alice = await agent('rp-a');
  const bob = await agent('rp-b');
  const opened = await alice.send(bob.identity.address, 'ping', { threadId: 'chat' });
  const [w] = await bob.inbox({ ack: true });
  const replied = await bob.reply(w, 'pong');
  assert.equal(replied.threadId, 'chat');
  assert.equal(replied.replyTo, opened.id);
  const [back] = await alice.inbox({ ack: true });
  assert.equal(back.text, 'pong');
  assert.equal(back.replyTo, opened.id);
});

test('threading to an opted-out recipient is dropped, delivered as a plain wire', async () => {
  const alice = await agent('drop-a');
  const bob = await agent('drop-b', { threading: false });
  const rec = await alice.lookup(bob.identity.address);
  assert.ok(!rec.capabilities.includes(WIRE_ENVELOPE_CAPABILITY));

  const sent = await alice.send(bob.identity.address, 'plain please', { threadId: 'nope', priority: 'high' });
  assert.equal(sent.threadingApplied, false);
  assert.ok(sent.threadingDropped);

  const [wire] = await bob.inbox({ ack: true });
  assert.equal(wire.text, 'plain please');
  assert.equal(wire.threadId, null);
  assert.equal(wire.verified, true);
});

test('the sent log carries the threading that was applied', async () => {
  const alice = await agent('snt-a');
  const bob = await agent('snt-b');
  await alice.send(bob.identity.address, 'logged', { threadId: 'T', replyTo: 'R' });
  const [copy] = await alice.sent();
  assert.equal(copy.text, 'logged');
  assert.equal(copy.threadId, 'T');
  assert.equal(copy.replyTo, 'R');
});

test('an invalid priority is rejected before hitting the relay', async () => {
  const alice = await agent('pr-a');
  const bob = await agent('pr-b');
  await assert.rejects(
    alice.send(bob.identity.address, 'hi', { priority: 'URGENT' }),
    /priority must be one of/,
  );
});
