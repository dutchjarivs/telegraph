// Threading — threadId / replyTo / priority carried E2E inside the sealed box.
// Two things must hold: the metadata round-trips for current-SDK peers, and an
// old (envelope-unaware) peer never receives anything but a plain string.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TelegraphClient, createIdentity, TelegraphError } from '../index.js';
import { packWire, unpackWire, groupThreads, WIRE_ENVELOPE_CAPABILITY } from '../index.js';
import { MockRelay } from '../mock.js';

function pair(relay) {
  const alice = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  const bob = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  return { alice, bob };
}

// --- pure pack/unpack ---

test('packWire stays a bare string when there is no threading metadata', () => {
  assert.equal(packWire('hello'), 'hello');
  // A message that happens to look like JSON is still sent verbatim.
  assert.equal(packWire('{"a":1}'), '{"a":1}');
});

test('packWire produces a marked envelope only when metadata is present', () => {
  const packed = packWire('hi', { threadId: 'T1', replyTo: 'M9', priority: 'high' });
  const obj = JSON.parse(packed);
  assert.equal(obj._tgv, 1);
  assert.equal(obj.text, 'hi');
  assert.equal(obj.threadId, 'T1');
  assert.equal(obj.replyTo, 'M9');
  assert.equal(obj.priority, 'high');
});

test('packWire rejects an unknown priority', () => {
  assert.throws(() => packWire('hi', { priority: 'urgent' }), RangeError);
});

test('unpackWire round-trips an envelope and reads a bare string as text', () => {
  const round = unpackWire(packWire('yo', { threadId: 'T', replyTo: 'R', priority: 'low' }));
  assert.deepEqual(round, { text: 'yo', threadId: 'T', replyTo: 'R', priority: 'low', attachments: [] });

  assert.deepEqual(unpackWire('just text'), { text: 'just text', threadId: null, replyTo: null, priority: null, attachments: [] });
});

test('unpackWire never mistakes ordinary JSON for an envelope (no _tgv marker)', () => {
  // Real message content that is itself JSON must come back byte-for-byte.
  const literal = '{"v":1,"text":"this is my actual message"}';
  assert.deepEqual(unpackWire(literal), { text: literal, threadId: null, replyTo: null, priority: null, attachments: [] });
  // Malformed JSON is text, not an error.
  assert.equal(unpackWire('{not json').text, '{not json');
  // Marker present but text missing → not a valid envelope, treated as text.
  assert.equal(unpackWire('{"_tgv":1}').text, '{"_tgv":1}');
});

test('unpackWire drops a malformed priority to null rather than trusting it', () => {
  const packed = JSON.stringify({ _tgv: 1, text: 'x', priority: 'nonsense' });
  assert.equal(unpackWire(packed).priority, null);
});

// --- end-to-end over the mock relay ---

test('a threaded wire round-trips: recipient sees threadId/replyTo/priority', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'alice' });
  await bob.register({ handle: 'bob' }); // threading:true by default → advertises the capability

  const sent = await alice.send('@bob', 'first in the thread', { threadId: 'campfire', priority: 'high' });
  assert.equal(sent.threadingApplied, true);
  assert.equal(sent.threadId, 'campfire');
  assert.equal(sent.priority, 'high');

  const [wire] = await bob.inbox({ ack: true });
  assert.equal(wire.text, 'first in the thread');
  assert.equal(wire.verified, true);
  assert.equal(wire.threadId, 'campfire');
  assert.equal(wire.priority, 'high');
  assert.equal(wire.replyTo, null);

  // The relay stored only ciphertext — the threadId is not readable on the wire.
  const stored = relay.mailboxes.get(bob.identity.address);
  // (already acked/removed; assert against a fresh send instead)
  assert.ok(Array.isArray(stored));
});

test('the relay cannot read threading metadata (it is sealed in the box)', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await alice.send('@b', 'hush', { threadId: 'secret-thread-xyz' });
  const stored = relay.mailboxes.get(bob.identity.address)[0];
  assert.ok(!stored.ciphertext.includes('secret-thread-xyz'));
  assert.equal(stored.threadId, undefined); // no plaintext threadId on the envelope
});

test('reply() continues the thread and sets replyTo to the original wire id', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });

  const opened = await alice.send('@b', 'ping', { threadId: 'chat-1' });
  const [wireForBob] = await bob.inbox({ ack: true });
  const replied = await bob.reply(wireForBob, 'pong');
  assert.equal(replied.threadId, 'chat-1');
  assert.equal(replied.replyTo, opened.id);

  const [wireForAlice] = await alice.inbox({ ack: true });
  assert.equal(wireForAlice.text, 'pong');
  assert.equal(wireForAlice.threadId, 'chat-1');
  assert.equal(wireForAlice.replyTo, opened.id);
});

test('reply() to a wire with no thread roots a new thread at that wire', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  const opened = await alice.send('@b', 'no thread here');
  const [w] = await bob.inbox({ ack: true });
  assert.equal(w.threadId, null);
  const replied = await bob.reply(w, 'starting a thread');
  assert.equal(replied.threadId, opened.id);
  assert.equal(replied.replyTo, opened.id);
});

test('threading is dropped (not sent as raw JSON) when the recipient cannot read it', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  // Bob opts out of the capability → simulates a 0.1.0 / envelope-unaware peer.
  await bob.register({ handle: 'b', threading: false });
  assert.ok(!(await alice.lookup('@b')).capabilities.includes(WIRE_ENVELOPE_CAPABILITY));

  const sent = await alice.send('@b', 'plain please', { threadId: 'nope', priority: 'high' });
  assert.equal(sent.threadingApplied, false);
  assert.ok(sent.threadingDropped);

  const [wire] = await bob.inbox({ ack: true });
  // Bob receives a clean plain message — never raw envelope JSON.
  assert.equal(wire.text, 'plain please');
  assert.equal(wire.threadId, null);
  assert.equal(wire.verified, true);
});

test("the sender's own sent() history carries the threading it applied", async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await alice.send('@b', 'logged with thread', { threadId: 'T-log', replyTo: 'R-log' });
  const [copy] = await alice.sent();
  assert.equal(copy.text, 'logged with thread');
  assert.equal(copy.threadId, 'T-log');
  assert.equal(copy.replyTo, 'R-log');
});

test('send() rejects an invalid priority before hitting the relay', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await assert.rejects(
    alice.send('@b', 'hi', { priority: 'CRITICAL' }),
    (e) => e instanceof TelegraphError && e.code === 'client_bad_argument',
  );
});

test('groupThreads buckets wires by thread, oldest-first within a thread', () => {
  const wires = [
    { id: 'm1', ts: 100, threadId: 'A' },
    { id: 'm2', ts: 300, threadId: 'B' },
    { id: 'm3', ts: 200, threadId: 'A' },
    { id: 'm4', ts: 50, threadId: null }, // lone wire → its own thread keyed by id
  ];
  const grouped = groupThreads(wires);
  const a = grouped.find((t) => t.threadId === 'A');
  assert.deepEqual(a.wires.map((w) => w.id), ['m1', 'm3']); // oldest-first
  assert.ok(grouped.find((t) => t.threadId === 'B'));
  assert.ok(grouped.find((t) => t.threadId === 'm4')); // keyed by its own id
  // Most-recently-active thread comes first (B's newest ts=300 beats A's 200).
  assert.equal(grouped[0].threadId, 'B');
});
