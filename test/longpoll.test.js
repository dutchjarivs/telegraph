// Long-poll inbox: GET /v1/inbox?wait=N holds the connection until a wire
// lands. The interesting cases are all about the three ways a held request can
// end — a wire arrives, the timer fires, the client hangs up — and making sure
// none of them leak a waiter or write to a dead socket.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';
import { authFields, signFields } from '../src/crypto.js';

let server;
let base;
let dataDir;
let alice;
let bob;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-longpoll-'));
  // A short cap keeps the "clamped to the max" test fast and honest.
  server = createServer({ dataDir, limits: { longPollMaxMs: 2_000 } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  alice = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  bob = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await alice.register({ handle: 'lp_alice', bio: 'sender' });
  await bob.register({ handle: 'lp_bob', bio: 'listener' });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('a wire already waiting comes back immediately, even with a long wait', async () => {
  await alice.send('@lp_bob', 'already here');
  const started = Date.now();
  const messages = await bob.inbox({ ack: true, wait: 60 });
  // The point: a full mailbox must not be held for the wait window.
  assert.ok(Date.now() - started < 1_000, 'should not have blocked');
  assert.equal(messages.length, 1);
  assert.equal(messages[0].text, 'already here');
});

test('an empty mailbox blocks, then delivers the moment a wire lands', async () => {
  const started = Date.now();
  // Start listening first, then send while the read is parked.
  const listening = bob.inbox({ ack: true, wait: 2 });
  await new Promise((r) => setTimeout(r, 150));
  await alice.send('@lp_bob', 'woke you up');
  const messages = await listening;
  const elapsed = Date.now() - started;

  assert.equal(messages.length, 1);
  assert.equal(messages[0].text, 'woke you up');
  assert.equal(messages[0].verified, true);
  // It woke on delivery, not on the timer: it answered well before the 2s cap
  // but only after the send that unblocked it.
  assert.ok(elapsed >= 150, `answered too early (${elapsed}ms) — did it actually wait?`);
  assert.ok(elapsed < 1_800, `answered on the timeout (${elapsed}ms), not on delivery`);
});

test('a wait that times out returns empty rather than erroring', async () => {
  const started = Date.now();
  const messages = await bob.inbox({ wait: 1 });
  const elapsed = Date.now() - started;
  assert.deepEqual(messages, []);
  // Held for roughly the requested window (a timeout is a normal, empty answer).
  assert.ok(elapsed >= 900, `did not hold the connection (${elapsed}ms)`);
});

test('wait is clamped to the relay maximum, not honoured blindly', async () => {
  // Server cap here is 2s; ask for an hour and it must still answer at the cap.
  const started = Date.now();
  const messages = await bob.inbox({ wait: 3600 });
  const elapsed = Date.now() - started;
  assert.deepEqual(messages, []);
  assert.ok(elapsed < 3_000, `ignored the cap and waited ${elapsed}ms`);
});

test('wait=0 is a plain non-blocking read (back-compat with old clients)', async () => {
  const started = Date.now();
  const messages = await bob.inbox(); // default wait = 0
  assert.deepEqual(messages, []);
  assert.ok(Date.now() - started < 500, 'a plain read must not block');
});

test('a garbage wait value is rejected instead of silently busy-polling', async () => {
  const res = await signedGet(bob, '/v1/inbox?wait=soon');
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, 'bad_wait');
});

test('a negative wait is rejected', async () => {
  const res = await signedGet(bob, '/v1/inbox?wait=-5');
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'bad_wait');
});

test('a long-poll still requires valid auth — you cannot park on someone else\'s mailbox', async () => {
  const res = await fetch(`${base}/v1/inbox?wait=30`); // no signature at all
  assert.equal(res.status, 401);
  assert.equal((await res.json()).error, 'missing_auth');
});

test('concurrent long-polls per address are capped', async () => {
  const limit = 8; // server default
  const controllers = [];
  const inflight = [];
  for (let i = 0; i < limit; i++) {
    const ctrl = new AbortController();
    controllers.push(ctrl);
    inflight.push(signedGet(bob, '/v1/inbox?wait=2', ctrl.signal).catch(() => null));
  }
  // Let the parked reads register before probing for the overflow.
  await new Promise((r) => setTimeout(r, 200));
  const overflow = await signedGet(bob, '/v1/inbox?wait=2');
  assert.equal(overflow.status, 429);
  assert.equal((await overflow.json()).error, 'too_many_waiters');

  for (const c of controllers) c.abort();
  await Promise.all(inflight);
});

test('a client that hangs up mid-wait frees its slot', async () => {
  // Fill every slot, drop them all, and confirm the relay accepts a fresh
  // long-poll — i.e. the abandoned waiters were unregistered, not leaked.
  const controllers = [];
  const inflight = [];
  for (let i = 0; i < 8; i++) {
    const ctrl = new AbortController();
    controllers.push(ctrl);
    inflight.push(signedGet(bob, '/v1/inbox?wait=2', ctrl.signal).catch(() => null));
  }
  await new Promise((r) => setTimeout(r, 200));
  for (const c of controllers) c.abort();
  await Promise.all(inflight);
  await new Promise((r) => setTimeout(r, 150)); // let the close events land

  const res = await signedGet(bob, '/v1/inbox?wait=0');
  assert.equal(res.status, 200, 'slots were not released after the clients hung up');
});

test('a delivery only wakes the recipient, not everyone waiting', async () => {
  // Alice parks on her own (empty) mailbox while a wire is sent to Bob.
  const aliceWaiting = alice.inbox({ wait: 2 });
  const bobWaiting = bob.inbox({ ack: true, wait: 2 });
  await new Promise((r) => setTimeout(r, 150));
  await alice.send('@lp_bob', 'for bob only');

  const bobMessages = await bobWaiting;
  assert.equal(bobMessages.length, 1);
  assert.equal(bobMessages[0].text, 'for bob only');

  // Alice's read was not woken by Bob's mail; it runs out its timer and is empty.
  const aliceMessages = await aliceWaiting;
  assert.deepEqual(aliceMessages, []);
});

test('a duplicate wire does not wake a listener (nothing new arrived)', async () => {
  // Send once and ack, then replay the exact envelope. The replay is deduped by
  // the seen-ledger, so a parked listener must stay parked — otherwise agents
  // get spurious wakeups from replayed traffic.
  await alice.send('@lp_bob', 'original');
  const [wire] = await bob.inbox({ ack: true });
  const envelope = wire.envelope;

  const started = Date.now();
  const listening = bob.inbox({ wait: 1 });
  await new Promise((r) => setTimeout(r, 100));
  const replay = await fetch(`${base}/v1/messages`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(envelope),
  }).then((r) => r.json());
  assert.equal(replay.duplicate, true);

  const messages = await listening;
  assert.deepEqual(messages, [], 'a deduped replay must not wake the listener');
  assert.ok(Date.now() - started >= 900, 'listener was woken early by the duplicate');
});

// The server holds long-polls open, and server.close() waits for open
// connections — so a parked read could stall shutdown forever. This is the
// regression guard for that: the whole suite would hang without the drain.
test('shutdown drains parked long-polls instead of hanging on them', async () => {
  const ownDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-lp-close-'));
  const own = createServer({ dataDir: ownDir });
  await new Promise((resolve) => own.listen(0, '127.0.0.1', resolve));
  const ownBase = `http://127.0.0.1:${own.address().port}`;
  const carol = new TelegraphClient({ server: ownBase, identity: TelegraphClient.generateIdentity() });
  await carol.register({ handle: 'lp_carol' });

  const parked = carol.inbox({ wait: 60 }).catch(() => 'connection dropped');
  await new Promise((r) => setTimeout(r, 200)); // ensure it is actually parked

  const closed = new Promise((resolve) => own.close(resolve));
  const outcome = await Promise.race([
    closed.then(() => 'closed'),
    new Promise((r) => setTimeout(() => r('HUNG'), 5_000)),
  ]);
  assert.equal(outcome, 'closed', 'server.close() hung on a parked long-poll');

  await parked; // the held request resolves (empty) rather than dangling
  fs.rmSync(ownDir, { recursive: true, force: true });
});

// Raw signed GET, for the cases the SDK deliberately won't let us express
// (garbage ?wait= values, deliberate overflow of the waiter cap, aborts).
// Signing is rebuilt from the spec here rather than reaching into the client's
// private #authHeaders — which also proves the auth format is reproducible from
// PROTOCOL.md alone, and that ?wait= stays outside the signature (the signature
// covers the pathname only, so old clients keep working against a new relay).
function signedGet(client, pathWithQuery, signal) {
  const { address, signSecretKey } = client.identity;
  const pathname = pathWithQuery.split('?')[0];
  const ts = Date.now();
  const bodyHash = createHash('sha256').update('', 'utf8').digest('hex');
  return fetch(`${base}${pathWithQuery}`, {
    signal,
    headers: {
      'x-telegraph-address': address,
      'x-telegraph-ts': String(ts),
      'x-telegraph-sig': signFields(authFields('GET', pathname, bodyHash, ts), signSecretKey),
    },
  });
}
