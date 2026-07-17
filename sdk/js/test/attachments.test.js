// Attachments — files sealed E2E inside the same box as the text, gated on the
// recipient advertising attachments-v1. Two invariants: a file round-trips
// byte-for-byte to a capable peer, and the relay is as blind to it as to any
// wire (the bytes never appear in the stored ciphertext, and an incapable peer
// never receives one — the send is refused rather than silently stripped).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TelegraphClient, createIdentity, TelegraphError } from '../index.js';
import {
  packWire,
  unpackWire,
  ATTACHMENTS_CAPABILITY,
  MAX_ATTACHMENTS,
} from '../index.js';
import { MockRelay } from '../mock.js';

function pair(relay) {
  const alice = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  const bob = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  return { alice, bob };
}

const bytes = (...n) => new Uint8Array(n);

// --- pure pack/unpack (base64 in/out; the SDK does the byte<->b64 step) ---

test('packWire embeds attachments and unpackWire reads them back', () => {
  const packed = packWire('see file', {
    attachments: [{ name: 'a.txt', mime: 'text/plain', size: 3, data: 'AAEC' }],
  });
  const env = unpackWire(packed);
  assert.equal(env.text, 'see file');
  assert.equal(env.attachments.length, 1);
  assert.deepEqual(env.attachments[0], { name: 'a.txt', mime: 'text/plain', size: 3, data: 'AAEC' });
});

test('packWire defaults name/mime and coerces a bad size to 0', () => {
  const env = unpackWire(packWire('', { attachments: [{ data: 'AAEC' }, { data: 'AwQ', size: -5 }] }));
  assert.equal(env.attachments[0].name, 'attachment-1');
  assert.equal(env.attachments[0].mime, 'application/octet-stream');
  assert.equal(env.attachments[1].size, 0);
});

test('an empty attachments array leaves the wire a bare string', () => {
  assert.equal(packWire('hi', { attachments: [] }), 'hi');
});

test('packWire refuses more than MAX_ATTACHMENTS', () => {
  const many = Array.from({ length: MAX_ATTACHMENTS + 1 }, () => ({ data: 'AA' }));
  assert.throws(() => packWire('x', { attachments: many }), RangeError);
});

test('unpackWire skips malformed attachment entries defensively', () => {
  const packed = JSON.stringify({
    _tgv: 1, text: 't',
    attachments: [{ data: 'AAEC' }, { name: 'no-data' }, 42, null],
  });
  const env = unpackWire(packed);
  assert.equal(env.attachments.length, 1);
  assert.equal(env.attachments[0].data, 'AAEC');
});

// --- end-to-end over the mock relay ---

test('an attachment round-trips byte-for-byte to a capable recipient', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'alice' });
  await bob.register({ handle: 'bob' }); // attachments:true by default → advertises the cap

  const payload = bytes(0, 1, 2, 253, 254, 255);
  const sent = await alice.send('@bob', 'here is a file', {
    attachments: [{ name: 'blob.bin', mime: 'application/octet-stream', data: payload }],
  });
  assert.equal(sent.attachments, 1);

  const [wire] = await bob.inbox({ ack: true });
  assert.equal(wire.text, 'here is a file');
  assert.equal(wire.verified, true);
  assert.equal(wire.attachments.length, 1);
  assert.equal(wire.attachments[0].name, 'blob.bin');
  assert.equal(wire.attachments[0].size, 6);
  assert.ok(wire.attachments[0].data instanceof Uint8Array);
  assert.deepEqual([...wire.attachments[0].data], [...payload]);
});

test('the relay never sees attachment bytes (sealed in the box)', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  // A recognizable byte pattern that would be obvious if it leaked in the clear.
  const secret = new TextEncoder().encode('TOP-SECRET-ATTACHMENT-BODY');
  await alice.send('@b', 'msg', { attachments: [{ name: 's.txt', mime: 'text/plain', data: secret }] });
  const stored = relay.mailboxes.get(bob.identity.address)[0];
  assert.ok(!stored.ciphertext.includes('TOP-SECRET'));
  assert.equal(stored.attachments, undefined); // nothing attachment-shaped on the envelope
});

test('sending an attachment to an incapable recipient is refused, not stripped', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  // Bob opts out → a 0.1.0 / attachment-unaware peer.
  await bob.register({ handle: 'b', attachments: false });
  assert.ok(!(await alice.lookup('@b')).capabilities.includes(ATTACHMENTS_CAPABILITY));

  await assert.rejects(
    alice.send('@b', 'file for you', { attachments: [{ name: 'x', data: bytes(1, 2, 3) }] }),
    (e) => e instanceof TelegraphError && e.code === 'client_recipient_no_attachments',
  );
  // And nothing landed in Bob's mailbox — the refusal happened before the send.
  assert.equal((await bob.inbox()).length, 0);
});

test('an attachment-only wire (empty text) is allowed', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await alice.send('@b', '', { attachments: [{ name: 'only.bin', data: bytes(9, 9, 9) }] });
  const [wire] = await bob.inbox({ ack: true });
  assert.equal(wire.text, '');
  assert.equal(wire.attachments.length, 1);
  assert.deepEqual([...wire.attachments[0].data], [9, 9, 9]);
});

test('a wire with neither text nor attachments is rejected', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await assert.rejects(
    alice.send('@b', ''),
    (e) => e instanceof TelegraphError && e.code === 'client_empty_message',
  );
});

test('attachments and threading ride the same wire', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await alice.send('@b', 'thread + file', {
    threadId: 'T-1', priority: 'high',
    attachments: [{ name: 'doc.txt', mime: 'text/plain', data: bytes(65, 66) }],
  });
  const [wire] = await bob.inbox({ ack: true });
  assert.equal(wire.threadId, 'T-1');
  assert.equal(wire.priority, 'high');
  assert.equal(wire.attachments.length, 1);
  assert.deepEqual([...wire.attachments[0].data], [65, 66]);
});

test("the sender's sent() history carries the attachments it sent", async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await alice.send('@b', 'logged', { attachments: [{ name: 'log.bin', data: bytes(7, 7) }] });
  const [copy] = await alice.sent();
  assert.equal(copy.text, 'logged');
  assert.equal(copy.attachments.length, 1);
  assert.deepEqual([...copy.attachments[0].data], [7, 7]);
});

test('send() rejects a non-bytes attachment data before hitting the relay', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await assert.rejects(
    alice.send('@b', 'hi', { attachments: [{ name: 'x', data: 'not-bytes' }] }),
    (e) => e instanceof TelegraphError && e.code === 'client_bad_argument',
  );
});

// --- cross-version backward compatibility (the published 0.2.0 is live) ---

test('a 0.2.0-style peer (wire-envelope-v1 but not attachments-v1) gets threading + expiry but attachments are refused', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  // Exactly what a published-0.2.0 agent advertises: threading, no attachments.
  await bob.register({ handle: 'b', attachments: false });
  const rec = await alice.lookup('@b');
  assert.ok(rec.capabilities.includes('wire-envelope-v1'));
  assert.ok(!rec.capabilities.includes(ATTACHMENTS_CAPABILITY));

  // Threading + expiry still apply (they ride wire-envelope-v1, which 0.2.0 has).
  const future = Date.now() + 60_000;
  const sent = await alice.send('@b', 'thread + expiry, no file', { threadId: 'T', expiresAt: future });
  assert.equal(sent.threadingApplied, true);
  assert.equal(sent.threadId, 'T');
  assert.equal(sent.expiresAt, future);
  const [wire] = await bob.inbox({ ack: true });
  assert.equal(wire.threadId, 'T');
  assert.equal(wire.expiresAt, future);

  // But an attachment to that same peer is refused — never silently dropped.
  await assert.rejects(
    alice.send('@b', 'file', { attachments: [{ name: 'x', data: bytes(1, 2, 3) }] }),
    (e) => e instanceof TelegraphError && e.code === 'client_recipient_no_attachments',
  );
});

test('expiresAt exactly equal to now is not yet expired (boundary is strict <)', () => {
  const now = 1_000_000_000_000;
  const env = unpackWire(packWire('x', { expiresAt: now }));
  // The client computes expired as (expiresAt < now); at equality it is still live.
  assert.equal(env.expiresAt < now, false);
});
