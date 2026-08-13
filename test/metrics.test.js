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

test('an accepted wire increments volume and tokens billed', async () => {
  const a = await agent('m-a');
  const b = await agent('m-b');
  const before = await metrics();
  await a.send('@m-b', 'x'); // 1-char = 1 token, fits the free:1 allowance
  const after = await metrics();
  assert.equal(after.wires.accepted, before.wires.accepted + 1);
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
  assert.equal(after.wires.accepted, before.wires.accepted + 1);
  assert.equal(after.wires.duplicate, before.wires.duplicate + 1);
  void b;
});

test('acking wires records a collection and its latency', async () => {
  const a = await agent('m-lat-a');
  const b = await agent('m-lat-b');
  await a.send('@m-lat-b', 'x');
  const before = await metrics();
  await b.inbox({ ack: true });
  const m = await metrics();
  assert.equal(m.wires.collected, before.wires.collected + 1);
  assert.equal(m.collectionLatencyMs.observations, before.collectionLatencyMs.observations + 1);
  assert.ok(m.collectionLatencyMs.p50 >= 0);
});

// The counters are only worth having if the sender's step and the recipient's
// step can move independently. An accepted wire nobody has collected must show
// up in exactly one of them.
test('accepting a wire does not count as collecting it', async () => {
  const a = await agent('m-sep-a');
  const b = await agent('m-sep-b');
  const before = await metrics();
  await a.send('@m-sep-b', 'x');
  const mid = await metrics();
  assert.equal(mid.wires.accepted, before.wires.accepted + 1);
  assert.equal(mid.wires.collected, before.wires.collected, 'nobody has acked it yet');
  await b.inbox({ ack: true });
  const after = await metrics();
  assert.equal(after.wires.collected, before.wires.collected + 1);
  assert.equal(after.wires.accepted, mid.wires.accepted, 'collecting must not re-count acceptance');
});

// Acks are idempotent on the mailbox, so they must be idempotent on the counter
// too — otherwise a client that retries an ack inflates the one number that is
// supposed to be the recipient's attestation.
test('re-acking an already-collected wire counts once', async () => {
  const a = await agent('m-re-a');
  const b = await agent('m-re-b');
  const sent = await a.send('@m-re-b', 'x');
  await b.inbox({ ack: true });
  const before = (await metrics()).wires.collected;
  await b.ack([sent.id]); // same id, second time
  assert.equal((await metrics()).wires.collected, before, 'the wire is already gone from the mailbox');
});

// Percentiles over a sliding window are a claim about a population, and the
// population is not the window once it saturates. Run past the cap and check
// the snapshot says so rather than reporting the window as if it were the total.
test('percentiles carry the denominator they were computed against', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-latwin-'));
  const srv = createServer({ dataDir: dir, adminToken: ADMIN, limits: { latencyWindow: 3, registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const b2 = `http://127.0.0.1:${srv.address().port}`;
  try {
    const mk = async (h) => {
      const c = new TelegraphClient({ server: b2, identity: TelegraphClient.generateIdentity() });
      await c.register({ handle: h });
      return c;
    };
    const a = await mk('w-a');
    const b = await mk('w-b');
    const snap = async () => (await (await fetch(b2 + '/v1/admin/overview', { headers: { 'x-telegraph-admin': ADMIN } })).json()).metrics;

    for (let i = 0; i < 3; i++) await a.send('@w-b', 'x');
    await b.inbox({ ack: true });
    let m = await snap();
    assert.equal(m.collectionLatencyMs.observations, 3);
    assert.equal(m.collectionLatencyMs.window, 3);
    assert.equal(m.collectionLatencyMs.windowCap, 3);
    assert.equal(m.collectionLatencyMs.truncated, false);

    for (let i = 0; i < 2; i++) await a.send('@w-b', 'y');
    await b.inbox({ ack: true });
    m = await snap();
    assert.equal(m.collectionLatencyMs.observations, 5, 'every collection counts');
    assert.equal(m.collectionLatencyMs.window, 3, 'the window stays capped');
    assert.equal(m.collectionLatencyMs.truncated, true, 'and the snapshot admits the two differ');
  } finally {
    await new Promise((r) => srv.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The negative control: a wire the relay accepted and billed for, which the
// recipient never got. Before this counter there was no row anywhere in the
// relay that could say it happened.
test('a wire that expires before collection is counted, not silently dropped', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-exp-'));
  const srv = createServer({ dataDir: dir, adminToken: ADMIN, limits: { messageTtlMs: 40, registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const b2 = `http://127.0.0.1:${srv.address().port}`;
  try {
    const mk = async (h) => {
      const c = new TelegraphClient({ server: b2, identity: TelegraphClient.generateIdentity() });
      await c.register({ handle: h });
      return c;
    };
    const a = await mk('x-a');
    const b = await mk('x-b');
    const snap = async () => (await (await fetch(b2 + '/v1/admin/overview', { headers: { 'x-telegraph-admin': ADMIN } })).json()).metrics;

    await a.send('@x-b', 'this one dies in the mailbox');
    const before = await snap();
    assert.equal(before.wires.accepted, 1, 'accepted and billed');
    assert.equal(before.wires.expiredUncollected, 0);

    await new Promise((r) => setTimeout(r, 80));
    const box = await b.inbox();
    assert.equal(box.length, 0, 'aged out before the recipient ever saw it');

    const after = await snap();
    assert.equal(after.wires.collected, 0, 'nobody collected it');
    assert.equal(after.wires.expiredUncollected, 1, 'and the relay keeps a record that it happened');
    assert.ok(after.tokensBilled > 0, 'the sender was charged for a wire nobody received');
  } finally {
    await new Promise((r) => srv.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
