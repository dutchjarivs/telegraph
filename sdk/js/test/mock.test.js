// The mock relay is the SDK's own first customer: if an agent can be built and
// exercised end-to-end against MockRelay with no network, so can a developer's.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { TelegraphClient, createIdentity, TelegraphError } from '../index.js';
import { MockRelay } from '../mock.js';

function pair(relay) {
  const alice = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  const bob = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  return { alice, bob };
}

test('a wire sent through the mock arrives decrypted and sender-verified', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'alice', bio: 'sender' });
  await bob.register({ handle: 'bob', bio: 'receiver' });

  const sent = await alice.send('@bob', 'meet at the ridge, sundown');
  assert.equal(sent.duplicate, false);
  assert.ok(sent.id);

  const wires = await bob.inbox({ ack: true });
  assert.equal(wires.length, 1);
  assert.equal(wires[0].text, 'meet at the ridge, sundown');
  assert.equal(wires[0].verified, true);
  assert.equal(wires[0].fromHandle, 'alice');

  // acked → gone
  assert.equal((await bob.inbox()).length, 0);
});

test('the relay cannot read the wire: ciphertext never equals the plaintext', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await alice.send(bob.identity.address, 'secret payload');
  const stored = relay.mailboxes.get(bob.identity.address)[0];
  assert.ok(!stored.ciphertext.includes('secret'));
  assert.notEqual(stored.ciphertext, 'secret payload');
});

test('sender keeps a decryptable self-sealed copy in sent()', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await alice.send('@b', 'for my own records');
  const log = await alice.sent();
  assert.equal(log.length, 1);
  assert.equal(log[0].text, 'for my own records');
});

test('a blocked sender is refused explicitly, not blackholed', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await bob.block('@a');
  await assert.rejects(
    alice.send('@b', 'let me in'),
    (e) => e instanceof TelegraphError && e.code === 'recipient_blocked_sender',
  );
  assert.equal((await bob.inbox()).length, 0);
});

test('a replayed envelope is reported as duplicate, not delivered twice', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  // A network retry replays the *same* signed body. Fresh send() calls each
  // pick a new nonce, so drop to the wire to reproduce a true replay.
  const { encrypt, signFields, messageFields } = await import('../src/crypto.js');
  const rec = await alice.lookup('@b');
  const { nonce, ciphertext } = encrypt('hi', rec.boxPublicKey, alice.identity.boxSecretKey);
  const ts = Date.now();
  const sig = signFields(messageFields(rec.address, alice.identity.address, nonce, ciphertext, ts), alice.identity.signSecretKey);
  const body = JSON.stringify({ to: rec.address, from: alice.identity.address, nonce, ciphertext, ts, sig });
  const post = () => relay.fetch('http://mock/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json' }, body }).then((r) => r.json());
  const first = await post();
  const second = await post();
  assert.equal(first.duplicate ?? false, false);
  assert.equal(second.duplicate, true);
  assert.equal((await bob.inbox()).length, 1);
});

test('registering a handle already taken by another key is rejected', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'samename' });
  await assert.rejects(
    bob.register({ handle: 'SameName' }),
    (e) => e instanceof TelegraphError && e.code === 'handle_taken',
  );
});

test('signed calls without an identity fail fast with client_no_identity', async () => {
  const relay = new MockRelay();
  const anon = new TelegraphClient({ fetch: relay.fetch });
  await assert.rejects(anon.inbox(), (e) => e instanceof TelegraphError && e.code === 'client_no_identity');
  await assert.rejects(anon.send('@x', 'hi'), (e) => e.code === 'client_no_identity');
});

test('an over-long wire is rejected client-side before any request', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'a' });
  await bob.register({ handle: 'b' });
  await assert.rejects(
    alice.send('@b', 'x'.repeat(4001)),
    (e) => e instanceof TelegraphError && e.code === 'client_message_too_long',
  );
});

test('listen() yields wires as an async generator', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'lstn-a' });
  await bob.register({ handle: 'lstn-b' });
  await alice.send('@lstn-b', 'streamed to you');
  // wait:0 → non-blocking; the queued wire comes out on the first iteration.
  let got = null;
  for await (const wire of bob.listen({ wait: 0, ack: true })) {
    got = wire;
    break; // stop after the first
  }
  assert.equal(got.text, 'streamed to you');
  assert.equal(got.verified, true);
});

test('allowlist strict mode: only listed senders get through (README methods exist)', async () => {
  const relay = new MockRelay();
  const alice = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  const bob = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  const eve = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  await alice.register({ handle: 'al' });
  await bob.register({ handle: 'bo' });
  await eve.register({ handle: 'ev' });

  // Bob builds his allowlist, then flips strict mode on.
  await bob.allow('@al');
  const modeOn = await bob.allowlistMode(true);
  assert.equal(modeOn.mode, true);
  const list = await bob.allowlist();
  assert.equal(list.count, 1);
  assert.equal(list.entries[0].handle, 'al');

  // Alice (allowlisted) gets through; Eve (not) is refused explicitly.
  await alice.send('@bo', 'i am on the list');
  await assert.rejects(
    eve.send('@bo', 'let me in'),
    (e) => e instanceof TelegraphError && e.code === 'recipient_not_accepting',
  );
  assert.equal((await bob.inbox()).length, 1);

  // disallow + mode off reopens the door.
  await bob.disallow('@al');
  await bob.allowlistMode(false);
  await eve.send('@bo', 'now?');
  assert.equal((await bob.inbox()).length, 2);
});

test('setQuota/getQuota round-trip through the client', async () => {
  const relay = new MockRelay();
  const bob = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  await bob.register({ handle: 'q-bob' });
  await bob.setQuota(5);
  assert.equal((await bob.getQuota()).perSenderDailyMax, 5);
});

test('per-sender quota is enforced at delivery, allowlisted senders exempt', async () => {
  const relay = new MockRelay();
  const bob = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  const eve = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  const fan = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  await bob.register({ handle: 'q2-bob' });
  await eve.register({ handle: 'q2-eve' });
  await fan.register({ handle: 'q2-fan' });

  // Bob caps non-allowlisted senders at 2 wires/day.
  await bob.setQuota(2);

  // Eve is not allowlisted: her first two land, the third is refused with 429.
  await eve.send('@q2-bob', 'one');
  await eve.send('@q2-bob', 'two');
  await assert.rejects(
    eve.send('@q2-bob', 'three'),
    (e) => e instanceof TelegraphError && e.code === 'sender_quota_exceeded',
  );

  // An allowlisted sender is exempt from the quota entirely.
  await bob.allow('@q2-fan');
  await fan.send('@q2-bob', 'a');
  await fan.send('@q2-bob', 'b');
  await fan.send('@q2-bob', 'c'); // past the cap, still delivered — exempt

  // Bob received 2 from Eve + 3 from the allowlisted fan = 5.
  assert.equal((await bob.inbox()).length, 5);
});

test('idempotencyKey collapses a retried send to one delivery', async () => {
  const relay = new MockRelay();
  const alice = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  const bob = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  await alice.register({ handle: 'idem-al' });
  await bob.register({ handle: 'idem-bo' });

  const first = await alice.send('@idem-bo', 'charge me once', { idempotencyKey: 'order-42' });
  assert.equal(first.idempotent, false);
  assert.equal(first.duplicate, false);

  // A retry under the same key returns the original id and is flagged idempotent.
  const retry = await alice.send('@idem-bo', 'charge me once', { idempotencyKey: 'order-42' });
  assert.equal(retry.idempotent, true);
  assert.equal(retry.id, first.id);

  // Only one wire actually landed in Bob's mailbox.
  assert.equal((await bob.inbox()).length, 1);

  // A different key is a distinct wire.
  const other = await alice.send('@idem-bo', 'a second order', { idempotencyKey: 'order-43' });
  assert.equal(other.idempotent, false);
  assert.equal((await bob.inbox()).length, 2);
});

test('an over-long idempotencyKey is rejected client-side before any request', async () => {
  const relay = new MockRelay();
  const alice = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  const bob = new TelegraphClient({ identity: createIdentity(), fetch: relay.fetch });
  await alice.register({ handle: 'idem-al2' });
  await bob.register({ handle: 'idem-bo2' });
  await assert.rejects(
    alice.send('@idem-bo2', 'hi', { idempotencyKey: 'x'.repeat(129) }),
    (e) => e instanceof TelegraphError && e.code === 'client_bad_argument',
  );
});

test('directory search finds an agent by handle and bio', async () => {
  const relay = new MockRelay();
  const { alice, bob } = pair(relay);
  await alice.register({ handle: 'weatherbot', bio: 'forecasts and radar' });
  await bob.register({ handle: 'newsbot', bio: 'headlines' });
  const byHandle = await alice.directory('weather');
  assert.equal(byHandle.count, 1);
  const byBio = await alice.directory('radar');
  assert.equal(byBio.count, 1);
  assert.equal(byBio.agents[0].verified, true);
});

test('a malformed relay response fails cleanly instead of throwing a TypeError', async () => {
  // The relay is only semi-trusted. If it returns a list field that isn't an
  // array (a bug, or a hostile relay), the SDK must not crash mid-.map() — it
  // should behave as "no results", which callers already handle.
  const identity = createIdentity();
  const badFetch = async (url) => ({
    ok: true,
    status: 200,
    json: async () => (String(url).includes('/v1/directory')
      ? { count: 0, agents: 'not-an-array' }
      : { messages: { not: 'an array' } }),
  });
  const client = new TelegraphClient({ identity, fetch: badFetch });
  assert.deepEqual(await client.inbox(), []);
  assert.deepEqual(await client.sent(), []);
  assert.deepEqual((await client.directory('x')).agents, []);
});
