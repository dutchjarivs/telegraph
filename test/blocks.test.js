// Personal block lists. Reporting is community moderation (three distinct
// victims, then the operator decides); blocking is the control one agent has
// over its own doorbell — immediate, unilateral, and effective on its own.
//
// The properties worth defending here: a blocked wire is never stored and never
// charged, blocking is honest to the sender rather than a silent blackhole, and
// a block follows the keypair so it can't be shed by re-registering.
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
let alice; // blocker
let spammer;
let carol; // uninvolved third party

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-blocks-'));
  server = createServer({ dataDir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  alice = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  spammer = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  carol = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await alice.register({ handle: 'blk_alice' });
  await spammer.register({ handle: 'blk_spammer' });
  await carol.register({ handle: 'blk_carol' });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('an unblocked sender gets through (baseline)', async () => {
  const r = await spammer.send('@blk_alice', 'first contact');
  assert.ok(r.id, 'send should return a wire id');
  const messages = await alice.inbox({ ack: true });
  assert.equal(messages.length, 1);
  assert.equal(messages[0].text, 'first contact');
});

test('blocking stops delivery, and says so instead of blackholing', async () => {
  await alice.block('@blk_spammer', { note: 'kept wiring me junk' });

  // Explicit rejection: a relay that answered "ok" and dropped the wire would be
  // lying to the sender — and, worse, billing them for a message never delivered.
  await assert.rejects(
    () => spammer.send('@blk_alice', 'buy my coin'),
    (err) => {
      assert.equal(err.status, 403);
      assert.equal(err.data.error, 'recipient_blocked_sender');
      return true;
    },
  );

  const messages = await alice.inbox();
  assert.deepEqual(messages, [], 'blocked wire must never reach the mailbox');
});

test('a blocked wire is not charged', async () => {
  const before = await spammer.credits();
  await assert.rejects(() => spammer.send('@blk_alice', 'x'.repeat(2000)));
  const after = await spammer.credits();
  // A big wire that would have cost real tokens: the meter must not have moved.
  assert.equal(after.usedToday, before.usedToday, 'blocked sender was charged for an undelivered wire');
  assert.equal(after.credits, before.credits);
});

test('a block is one-way and specific — others are unaffected', async () => {
  // Carol, who is not blocked, still gets through to Alice.
  const r = await carol.send('@blk_alice', 'still friends');
  assert.ok(r.id);
  assert.equal((await alice.inbox({ ack: true })).length, 1);

  // And Alice blocking the spammer does not stop Alice reaching the spammer.
  const back = await alice.send('@blk_spammer', 'i blocked you, not the reverse');
  assert.ok(back.id);
  assert.equal((await spammer.inbox({ ack: true })).length, 1);
});

test('blocks list shows who you blocked, newest first, with the handle resolved', async () => {
  const blocks = await alice.blocks();
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].address, spammer.identity.address);
  assert.equal(blocks[0].handle, 'blk_spammer');
  assert.equal(blocks[0].note, 'kept wiring me junk');
  assert.equal(typeof blocks[0].at, 'number');
});

test('unblocking restores delivery', async () => {
  const r = await alice.unblock('@blk_spammer');
  assert.equal(r.ok, true);
  assert.equal(r.count, 0);
  assert.deepEqual(await alice.blocks(), []);

  const sent = await spammer.send('@blk_alice', 'second chance');
  assert.ok(sent.id);
  assert.equal((await alice.inbox({ ack: true }))[0].text, 'second chance');
});

test('blocking is idempotent and does not inflate the list', async () => {
  await alice.block('@blk_spammer');
  const twice = await alice.block('@blk_spammer', { note: 'again' });
  assert.equal(twice.count, 1, 're-blocking must not add a second entry');
  assert.equal((await alice.blocks()).length, 1);
  await alice.unblock('@blk_spammer');
});

test('unblocking someone who was never blocked is a clean 404, not a silent ok', async () => {
  await assert.rejects(
    () => alice.unblock('@blk_carol'),
    (err) => {
      assert.equal(err.status, 404);
      assert.equal(err.data.error, 'not_blocked');
      return true;
    },
  );
});

test('you cannot block yourself', async () => {
  await assert.rejects(
    () => alice.block(alice.identity.address),
    (err) => {
      assert.equal(err.data.error, 'cannot_block_self');
      return true;
    },
  );
});

// The anti-evasion property. Blocks are keyed by address, and an address is
// derived from the signing key — so leaving the relay and coming back cannot
// clear a block. Same keys, same address, still blocked.
test('a blocked agent cannot shed the block by re-registering', async () => {
  await alice.block('@blk_spammer');
  // Re-register from scratch with the same identity (new handle, new bio).
  await spammer.register({ handle: 'blk_reformed', bio: 'totally new agent, promise' });

  await assert.rejects(
    () => spammer.send('@blk_alice', 'its me again'),
    (err) => {
      assert.equal(err.data.error, 'recipient_blocked_sender');
      return true;
    },
  );
  await alice.unblock(spammer.identity.address);
});

test('you can block an address that is not registered on this relay', async () => {
  // Pre-emptive blocking has to work: you might have the address of a known bad
  // actor before (or after) it exists here, and an agent removed by the operator
  // can always re-register with the same keys.
  const stranger = TelegraphClient.generateIdentity();
  const r = await alice.block(stranger.address);
  assert.equal(r.ok, true);
  assert.equal(r.blocked, stranger.address);
  await alice.unblock(stranger.address);
});

test('a malformed address is rejected rather than stored', async () => {
  const res = await rawSigned(alice, 'POST', '/v1/blocks', { address: 'not-an-address' });
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'bad_address');
});

// A bare object-key lookup on "__proto__" resolves to a prototype member, which
// could make isBlocked() report a block that was never set (or miss one).
test('prototype-polluting addresses cannot forge a block', async () => {
  for (const nasty of ['__proto__', 'constructor', 'toString']) {
    const res = await rawSigned(alice, 'POST', '/v1/blocks', { address: nasty });
    assert.equal(res.status, 400, `${nasty} should be rejected as a bad address`);
  }
  // And a normal sender is still not blocked after those attempts.
  const r = await carol.send('@blk_alice', 'unaffected');
  assert.ok(r.id);
  await alice.inbox({ ack: true });
});

test('blocks require auth — you cannot read or edit someone else\'s list', async () => {
  const unsigned = await fetch(`${base}/v1/blocks`);
  assert.equal(unsigned.status, 401);

  const write = await fetch(`${base}/v1/blocks`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ address: carol.identity.address }),
  });
  assert.equal(write.status, 401);
});

test('the block list survives a relay restart', async () => {
  await alice.block('@blk_carol', { note: 'persisted?' });

  // Fresh server over the same data dir — blocks must come back off disk.
  await new Promise((resolve) => server.close(resolve));
  server = createServer({ dataDir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;
  base = `http://127.0.0.1:${port}`;
  for (const c of [alice, spammer, carol]) c.server = base;

  const blocks = await alice.blocks();
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].address, carol.identity.address);
  assert.equal(blocks[0].note, 'persisted?');

  await assert.rejects(() => carol.send('@blk_alice', 'after restart'));
  await alice.unblock('@blk_carol');
});

// Raw signed request, for inputs the SDK won't let us build (malformed addresses).
function rawSigned(client, method, pathname, body) {
  const raw = JSON.stringify(body);
  const { address, signSecretKey } = client.identity;
  const ts = Date.now();
  const bodyHash = createHash('sha256').update(raw, 'utf8').digest('hex');
  return fetch(`${base}${pathname}`, {
    method,
    headers: {
      'content-type': 'application/json',
      'x-telegraph-address': address,
      'x-telegraph-ts': String(ts),
      'x-telegraph-sig': signFields(authFields(method, pathname, bodyHash, ts), signSecretKey),
    },
    body: raw,
  });
}
