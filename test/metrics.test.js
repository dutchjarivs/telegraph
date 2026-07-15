// Operator dashboard metrics: the relay counts wire volume, policy rejections
// (failed deliveries), tokens billed, and collection latency, and surfaces them
// under admin-overview.metrics with a sinceStart stamp so they read as
// per-uptime figures, not all-time totals.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

const ADMIN = 'metrics-admin';
let server;
let base;
let dataDir;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-metrics-'));
  // freeDailyTokens: 1 so a second short wire from the same sender exhausts the
  // allowance and produces a payment_required rejection to count.
  server = createServer({ dataDir, adminToken: ADMIN, limits: { freeDailyTokens: 1, registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((r) => server.close(r));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

async function metrics() {
  const res = await fetch(base + '/v1/admin/overview', { headers: { 'x-telegraph-admin': ADMIN } });
  return (await res.json()).metrics;
}
const agent = async (h) => {
  const c = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await c.register({ handle: h });
  return c;
};

test('a delivered wire increments volume and tokens billed', async () => {
  const a = await agent('m-a');
  const b = await agent('m-b');
  const before = await metrics();
  await a.send('@m-b', 'x'); // 1-char = 1 token, fits the free:1 allowance
  const after = await metrics();
  assert.equal(after.wires.delivered, before.wires.delivered + 1);
  assert.ok(after.tokensBilled > before.tokensBilled);
  assert.ok(typeof after.sinceStart === 'number');
  void b;
});

test('a blocked send is counted as a rejection by reason', async () => {
  const a = await agent('m-blk-a');
  const b = await agent('m-blk-b');
  await b.block('@m-blk-a');
  const before = (await metrics()).wires.rejectedByReason.recipient_blocked_sender ?? 0;
  await assert.rejects(a.send('@m-blk-b', 'let me in'));
  const after = (await metrics()).wires.rejectedByReason.recipient_blocked_sender ?? 0;
  assert.equal(after, before + 1);
});

test('exhausting the free allowance is counted as payment_required', async () => {
  const a = await agent('m-pay-a');
  const b = await agent('m-pay-b');
  await a.send('@m-pay-b', 'x'); // uses the single free token
  const before = (await metrics()).wires.rejectedByReason.payment_required ?? 0;
  await assert.rejects(a.send('@m-pay-b', 'y')); // over budget now
  const after = (await metrics()).wires.rejectedByReason.payment_required ?? 0;
  assert.equal(after, before + 1);
});

test('a duplicate/idempotent send is counted separately, not as a delivery', async () => {
  const a = await agent('m-dup-a');
  const b = await agent('m-dup-b');
  const before = await metrics();
  await a.send('@m-dup-b', 'once', { idempotencyKey: 'k1' });
  await a.send('@m-dup-b', 'once', { idempotencyKey: 'k1' }); // idempotent replay
  const after = await metrics();
  assert.equal(after.wires.delivered, before.wires.delivered + 1);
  assert.equal(after.wires.duplicate, before.wires.duplicate + 1);
  void b;
});

test('acking wires records collection-latency samples', async () => {
  const a = await agent('m-lat-a');
  const b = await agent('m-lat-b');
  await a.send('@m-lat-b', 'x');
  const before = (await metrics()).collectionLatencyMs.samples;
  await b.inbox({ ack: true });
  const m = await metrics();
  assert.equal(m.collectionLatencyMs.samples, before + 1);
  assert.ok(m.collectionLatencyMs.p50 >= 0);
});
