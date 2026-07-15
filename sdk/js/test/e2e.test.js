// End-to-end against the real relay: boots ../../../src/server.js on an
// ephemeral port with a throwaway data dir and drives it through the published
// SDK surface. This is the test that proves the SDK speaks the actual protocol,
// not just the mock's idea of it. The temp dir is created under the OS temp
// root and removed after, so it can never touch a live data/ directory.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../../../src/server.js';
import { TelegraphClient, createIdentity, TelegraphError } from '../index.js';

let server;
let base;
let dataDir;

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-sdk-e2e-'));
  // All test agents share 127.0.0.1, so lift the anti-sybil per-IP cap that
  // production runs (5/hour) — otherwise the 6th registration in the suite 429s.
  server = createServer({ dataDir, limits: { registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

function client(identity) {
  return new TelegraphClient({ server: base, identity });
}

test('health reports a telegraph relay', async () => {
  const tg = client();
  const h = await tg.health();
  assert.equal(h.service, 'telegraph');
});

test('full loop: register → lookup → send → inbox(ack) → sent', async () => {
  const alice = client(createIdentity());
  const bob = client(createIdentity());
  await alice.register({ handle: 'e2e-alice', bio: 'sends', capabilities: ['test'] });
  await bob.register({ handle: 'e2e-bob', bio: 'receives' });

  const rec = await bob.lookup('@e2e-bob');
  assert.equal(rec.verified, true);
  assert.equal(rec.address, bob.identity.address);

  const sent = await alice.send('@e2e-bob', 'the sun is over the yardarm');
  assert.equal(sent.duplicate, false);
  assert.ok(sent.tokens >= 1);

  const wires = await bob.inbox({ ack: true });
  assert.equal(wires.length, 1);
  assert.equal(wires[0].text, 'the sun is over the yardarm');
  assert.equal(wires[0].verified, true);
  assert.equal(wires[0].fromHandle, 'e2e-alice');

  const log = await alice.sent();
  assert.equal(log.at(-1).text, 'the sun is over the yardarm');

  // acked, so the mailbox is empty now
  assert.equal((await bob.inbox()).length, 0);
});

test('sending to an unknown handle raises a typed not_found error', async () => {
  const alice = client(createIdentity());
  await alice.register({ handle: 'e2e-lonely' });
  await assert.rejects(
    alice.send('@nobody-here', 'anyone?'),
    (e) => e instanceof TelegraphError && e.status === 404,
  );
});

test('credits reflect the free daily allowance', async () => {
  const a = client(createIdentity());
  await a.register({ handle: 'e2e-credits' });
  const c = await a.credits();
  assert.ok(c.freeDailyTokens > 0);
  assert.equal(c.freeRemainingToday, c.freeDailyTokens);
});

test('block then send is refused with recipient_blocked_sender', async () => {
  const spammer = client(createIdentity());
  const target = client(createIdentity());
  await spammer.register({ handle: 'e2e-spammer' });
  await target.register({ handle: 'e2e-target' });
  await target.block('@e2e-spammer', { note: 'go away' });
  await assert.rejects(
    spammer.send('@e2e-target', 'buy my coin'),
    (e) => e instanceof TelegraphError && e.code === 'recipient_blocked_sender',
  );
  assert.deepEqual((await target.blocks()).map((b) => b.address), [spammer.identity.address]);
});

test('signed calls carry auth headers the relay accepts (inbox round-trips)', async () => {
  // A signed GET that the relay authenticates proves the SDK's request-signing
  // (address/ts/sig over method+path+bodyHash) matches what the relay verifies.
  const a = client(createIdentity());
  await a.register({ handle: 'e2e-signed' });
  const wires = await a.inbox();
  assert.deepEqual(wires, []);
});
