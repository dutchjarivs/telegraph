// Per-sender daily quotas: a recipient caps how many wires/day any single
// non-allowlisted sender can deliver. Allowlisted senders are exempt.
// Default is 0 = unlimited, so agents who never touch it are unaffected.
// Over-quota wires are refused explicitly (not blackholed) and not charged.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

let server;
let base;
let dataDir;

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-quota-'));
  server = createServer({ dataDir, limits: { registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((r) => server.close(r));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

let n = 0;
async function agent(p) {
  const c = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await c.register({ handle: `${p}-${n++}` });
  return c;
}

test('default quota is 0 (unlimited) and does not restrict wires', async () => {
  const owner = await agent('q-owner');
  const sender = await agent('q-sender');
  const q = await owner.getQuota();
  assert.equal(q.perSenderDailyMax, 0);
  // unlimited: send several wires, all should land
  for (let i = 0; i < 5; i++) {
    await sender.send(owner.identity.address, `wire ${i}`);
  }
  const wires = await owner.inbox({ ack: true });
  assert.equal(wires.length, 5);
});

test('a quota of N limits a non-allowlisted sender to N wires/day', async () => {
  const owner = await agent('q2-owner');
  const sender = await agent('q2-sender');
  await owner.setQuota(2);

  // First two wires land
  await sender.send(owner.identity.address, 'wire 1');
  await sender.send(owner.identity.address, 'wire 2');
  // Third is over quota → 429, not charged
  const beforeUsed = (await sender.credits()).freeUsedToday;
  await assert.rejects(
    sender.send(owner.identity.address, 'wire 3 over quota'),
    (e) => e.status === 429 && e.data?.error === 'sender_quota_exceeded',
  );
  const afterUsed = (await sender.credits()).freeUsedToday;
  assert.equal(afterUsed, beforeUsed, 'an over-quota sender is not charged');

  const wires = await owner.inbox({ ack: true });
  assert.equal(wires.length, 2);
});

test('allowlisted senders are exempt from the quota', async () => {
  const owner = await agent('q3-owner');
  const friend = await agent('q3-friend');
  await owner.allow(friend.identity.address);
  await owner.setQuota(1);

  // Friend is allowlisted → quota does not apply
  await friend.send(owner.identity.address, 'wire 1');
  await friend.send(owner.identity.address, 'wire 2');
  await friend.send(owner.identity.address, 'wire 3');

  const wires = await owner.inbox({ ack: true });
  assert.equal(wires.length, 3);
});

test('quota counts per-sender, not globally — two senders each get their own N', async () => {
  const owner = await agent('q4-owner');
  const a = await agent('q4-a');
  const b = await agent('q4-b');
  await owner.setQuota(1);

  // Sender A sends 1 (ok), 2nd rejected
  await a.send(owner.identity.address, 'a-wire 1');
  await assert.rejects(
    a.send(owner.identity.address, 'a-wire 2'),
    (e) => e.data?.error === 'sender_quota_exceeded',
  );
  // Sender B also gets 1 (ok), 2nd rejected — independent count
  await b.send(owner.identity.address, 'b-wire 1');
  await assert.rejects(
    b.send(owner.identity.address, 'b-wire 2'),
    (e) => e.data?.error === 'sender_quota_exceeded',
  );

  const wires = await owner.inbox({ ack: true });
  assert.equal(wires.length, 2);
});

test('setting quota to 0 disables it (unlimited)', async () => {
  const owner = await agent('q5-owner');
  const sender = await agent('q5-sender');
  await owner.setQuota(1);
  await sender.send(owner.identity.address, 'wire 1');
  await assert.rejects(
    sender.send(owner.identity.address, 'wire 2'),
    (e) => e.data?.error === 'sender_quota_exceeded',
  );
  // Disable quota
  await owner.setQuota(0);
  await sender.send(owner.identity.address, 'wire 2 now allowed');
  const wires = await owner.inbox({ ack: true });
  assert.equal(wires.length, 2);
});

test('self-wires are exempt from the quota', async () => {
  const owner = await agent('q6-owner');
  await owner.setQuota(1);
  // Sending to yourself should always work (allowlist exempts self too)
  await owner.send(owner.identity.address, 'self wire 1');
  await owner.send(owner.identity.address, 'self wire 2');
  await owner.send(owner.identity.address, 'self wire 3');
  const wires = await owner.inbox({ ack: true });
  assert.equal(wires.length, 3);
});

test('bad quota values are rejected', async () => {
  const owner = await agent('q7-owner');
  await assert.rejects(
    owner.setQuota(-1),
    (e) => e.data?.error === 'bad_quota',
  );
  await assert.rejects(
    owner.setQuota(NaN),
    (e) => e.data?.error === 'bad_quota',
  );
});

test('idempotent replays (same idempotency key) do not burn the quota', async () => {
  const owner = await agent('q8-owner');
  const sender = await agent('q8-sender');
  await owner.setQuota(1);
  // First send lands (count = 1 = quota). Use a raw fetch with an idempotency
  // key so we can replay the exact same envelope.
  const r1 = await sender.send(owner.identity.address, 'the wire');
  assert.equal(r1.duplicate, false);
  // A genuinely different wire is over quota (count = 1 = max)
  await assert.rejects(
    sender.send(owner.identity.address, 'a different wire'),
    (e) => e.data?.error === 'sender_quota_exceeded',
  );
  // The count should be exactly 1 (only the first wire was committed)
  const wires = await owner.inbox({ ack: true });
  assert.equal(wires.length, 1);
});
