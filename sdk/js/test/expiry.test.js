// Per-message expiry — an absolute `expiresAt` (or relative `ttlMs`) the sender
// seals E2E into the wire. It's advisory and relay-blind: the relay still stores
// and forwards the wire; the recipient client is what honors the expiry. Two
// things must hold — it round-trips to a capable peer, and the recipient can
// tell a stale wire (`expired: true`) and optionally drop it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TelegraphClient, createIdentity, TelegraphError } from '../index.js';
import { packWire, unpackWire } from '../index.js';
import { MockRelay } from '../mock.js';

function pair(relay) {
  const alice = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  const bob = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  return { alice, bob };
}

// --- pure pack/unpack ---

test('packWire carries a positive-integer expiresAt and unpackWire reads it', () => {
  const env = unpackWire(packWire('soon', { expiresAt: 1893456000000 }));
  assert.equal(env.expiresAt, 1893456000000);
});

test('packWire rejects a non-positive or non-integer expiresAt', () => {
  assert.throws(() => packWire('x', { expiresAt: 0 }), RangeError);
  assert.throws(() => packWire('x', { expiresAt: -5 }), RangeError);
  assert.throws(() => packWire('x', { expiresAt: 1.5 }), RangeError);
});

test('unpackWire drops a malformed expiresAt to null', () => {
  assert.equal(unpackWire('{"_tgv":1,"text":"x","expiresAt":"soon"}').expiresAt, null);
  assert.equal(unpackWire('{"_tgv":1,"text":"x","expiresAt":-1}').expiresAt, null);
});

// --- end-to-end over the mock relay ---

test('a future expiry round-trips and the wire is not expired', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  const future = Date.now() + 60_000;
  const sent = await alice.send('@b', 'valid for a minute', { expiresAt: future });
  assert.equal(sent.expiresAt, future);
  const [wire] = await bob.inbox({ ack: true });
  assert.equal(wire.expiresAt, future);
  assert.equal(wire.expired, false);
});

test('ttlMs is turned into an absolute expiresAt', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  const before = Date.now();
  const sent = await alice.send('@b', 'ttl', { ttlMs: 30_000 });
  assert.ok(sent.expiresAt >= before + 30_000 && sent.expiresAt <= Date.now() + 30_000);
});

test('a past expiry is flagged expired, and dropExpired filters it out', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  // An already-past expiry (still a valid positive integer).
  await alice.send('@b', 'stale', { expiresAt: 1 });

  // Default: the expired wire is returned, flagged — nothing hidden silently.
  const seen = await bob.inbox();
  assert.equal(seen.length, 1);
  assert.equal(seen[0].expired, true);
  assert.equal(seen[0].text, 'stale');

  // dropExpired filters it from the view (and ack still clears the mailbox).
  const filtered = await bob.inbox({ ack: true, dropExpired: true });
  assert.equal(filtered.length, 0);
  assert.equal((await bob.inbox()).length, 0, 'the expired wire was acked out of the mailbox');
});

test('expiry is dropped to null for a recipient that cannot read envelopes', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b', threading: false }); // no wire-envelope-v1
  const sent = await alice.send('@b', 'plain', { expiresAt: Date.now() + 1000 });
  assert.equal(sent.expiresAt, null);
  assert.equal(sent.threadingApplied, false);
  const [wire] = await bob.inbox({ ack: true });
  assert.equal(wire.text, 'plain'); // clean plain message, never raw JSON
  assert.equal(wire.expiresAt, null);
});

test('send() rejects a bad ttlMs before hitting the relay', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await assert.rejects(
    alice.send('@b', 'x', { ttlMs: -1 }),
    (e) => e instanceof TelegraphError && e.code === 'client_bad_argument',
  );
});
