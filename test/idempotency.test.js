// Idempotency keys on send: a retried send under the same key collapses to the
// first delivery — no second wire, no second charge — while distinct senders,
// distinct keys, and keyless sends are unaffected.
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

let server;
let base;
let dataDir;

function boot(dir) {
  const s = createServer({ dataDir: dir, limits: { registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  return s;
}

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-idem-'));
  server = boot(dataDir);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((r) => server.close(r));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

async function agent(handle) {
  const c = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await c.register({ handle });
  return c;
}

let n = 0;
const uniq = (p) => `${p}-${Date.now().toString(36)}-${n++}`;

test('a retried send with the same key delivers once and charges once', async () => {
  const alice = await agent(uniq('idem-a'));
  const bob = await agent(uniq('idem-b'));
  const key = 'order-42';

  const before = (await alice.credits()).freeUsedToday;
  const first = await alice.send(bob.identity.address, 'process order 42', { idempotencyKey: key });
  assert.equal(first.duplicate, false);
  assert.equal(first.idempotent, false);
  const afterFirst = (await alice.credits()).freeUsedToday;
  assert.ok(afterFirst > before, 'first send should charge');

  const second = await alice.send(bob.identity.address, 'process order 42', { idempotencyKey: key });
  assert.equal(second.idempotent, true);
  assert.equal(second.duplicate, true);
  assert.equal(second.id, first.id, 'idempotent replay returns the original wire id');

  const afterSecond = (await alice.credits()).freeUsedToday;
  assert.equal(afterSecond, afterFirst, 'idempotent replay must not charge again');

  const wires = await bob.inbox({ ack: true });
  assert.equal(wires.length, 1, 'only one wire delivered');
  assert.equal(wires[0].text, 'process order 42');
});

test('the same key from two different senders is independent', async () => {
  const a = await agent(uniq('idem-s1'));
  const b = await agent(uniq('idem-s2'));
  const target = await agent(uniq('idem-t'));
  await a.send(target.identity.address, 'from a', { idempotencyKey: 'shared' });
  await b.send(target.identity.address, 'from b', { idempotencyKey: 'shared' });
  const wires = await target.inbox({ ack: true });
  assert.equal(wires.length, 2, 'a key is scoped per sender, so both deliver');
});

test('without a key, two sends of the same text both deliver (no accidental dedup)', async () => {
  const a = await agent(uniq('idem-nk1'));
  const t = await agent(uniq('idem-nk2'));
  await a.send(t.identity.address, 'same text');
  await a.send(t.identity.address, 'same text');
  const wires = await t.inbox({ ack: true });
  assert.equal(wires.length, 2);
});

test('a "__proto__" key is treated as an ordinary key, not prototype pollution', async () => {
  const a = await agent(uniq('idem-pp1'));
  const t = await agent(uniq('idem-pp2'));
  const r1 = await a.send(t.identity.address, 'proto test', { idempotencyKey: '__proto__' });
  const r2 = await a.send(t.identity.address, 'proto test', { idempotencyKey: '__proto__' });
  assert.equal(r2.idempotent, true);
  assert.equal(r2.id, r1.id);
  assert.equal((await t.inbox({ ack: true })).length, 1);
  // The ledger object is still a plain object with an intact prototype.
  const ledger = JSON.parse(fs.readFileSync(path.join(dataDir, 'idempotency', a.identity.address.replace(/[^A-Za-z0-9-]/g, '') + '.json'), 'utf8'));
  assert.equal(Object.getPrototypeOf(ledger), Object.prototype);
});

test('an empty or over-long idempotency key is rejected', async () => {
  const a = await agent(uniq('idem-bad1'));
  const t = await agent(uniq('idem-bad2'));
  await assert.rejects(a.send(t.identity.address, 'x', { idempotencyKey: '' }), /empty message|bad_idempotency_key|400/);
  await assert.rejects(
    a.send(t.identity.address, 'x', { idempotencyKey: 'k'.repeat(129) }),
    (e) => e.status === 400 && e.data?.error === 'bad_idempotency_key',
  );
});

test('idempotency survives a relay restart (ledger is persisted)', async () => {
  const a = await agent(uniq('idem-rs1'));
  const t = await agent(uniq('idem-rs2'));
  const key = 'persist-me';
  const first = await a.send(t.identity.address, 'durable', { idempotencyKey: key });

  // Restart the relay against the same data dir.
  await new Promise((r) => server.close(r));
  server = boot(dataDir);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
  const a2 = new TelegraphClient({ server: base, identity: a.identity });
  const t2 = new TelegraphClient({ server: base, identity: t.identity });

  const second = await a2.send(t2.identity.address, 'durable', { idempotencyKey: key });
  assert.equal(second.idempotent, true);
  assert.equal(second.id, first.id);
  assert.equal((await t2.inbox({ ack: true })).length, 1, 'still just one wire after restart');
});
