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

// The counter above can only move inside the TTL prune. This relay runs with no
// TTL, so on the live service `expiredUncollected` is pinned at 0 by
// configuration and reports the same value a TTL-enabled relay shows when
// nothing has aged out. Two readings that mean different things must not
// serialise identically, and the second witness has to be able to disagree with
// the first — otherwise it is the counter's echo, not a check on it.
test('with expiry off the counter says so, and the parked wires dissent from it', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-parked-'));
  const srv = createServer({ dataDir: dir, adminToken: ADMIN, limits: { registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const b2 = `http://127.0.0.1:${srv.address().port}`;
  try {
    const mk = async (h) => {
      const c = new TelegraphClient({ server: b2, identity: TelegraphClient.generateIdentity() });
      await c.register({ handle: h });
      return c;
    };
    const a = await mk('p-a');
    const b = await mk('p-b');
    const snap = async () => (await (await fetch(b2 + '/v1/admin/overview', { headers: { 'x-telegraph-admin': ADMIN } })).json()).metrics;

    const empty = await snap();
    assert.equal(empty.wires.expiry.enabled, false, 'no TTL configured');
    assert.equal(empty.wires.expiry.expiredUncollectedCanFire, false, 'so the counter is incapable of moving');
    assert.equal(empty.wires.parked.wires, 0);
    assert.equal(empty.wires.parked.oldestAgeMs, null, 'no parked wire is null, not zero');

    await a.send('@p-b', 'nobody is coming for this one');
    const parked = await snap();
    // The whole point: same 0 on the counter, different reading beside it.
    assert.equal(parked.wires.expiredUncollected, 0, 'unchanged, as it structurally must be');
    assert.equal(parked.wires.parked.wires, 1, 'while the disk says a wire is sitting uncollected');
    assert.equal(parked.wires.parked.mailboxes, 1);
    assert.ok(parked.wires.parked.oldestAgeMs >= 0, 'and how long it has been waiting');
    assert.ok(parked.wires.parked.oldestReceivedAt <= Date.now());

    await b.inbox({ ack: true });
    const drained = await snap();
    assert.equal(drained.wires.parked.wires, 0, 'collection clears it; a counter would not have');
    assert.equal(drained.wires.parked.oldestAgeMs, null);
  } finally {
    await new Promise((r) => srv.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The parked census is the only reader that can contradict `expiredUncollected`,
// so its own read failures have to be visible. They were not: an unparseable
// mailbox file left the loop through the same `continue` as an empty one, which
// makes a corrupted mailbox report as a mailbox holding nothing. That is silent
// in the flattering direction — it lowers the wire count and can move
// `oldestReceivedAt` toward the present, improving the neglect figure precisely
// because the evidence stopped being readable. A check needs an input that makes
// it go red; this is that input.
test('an unreadable mailbox is counted, not silently read as an empty one', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-unreadable-'));
  const srv = createServer({ dataDir: dir, adminToken: ADMIN, limits: { registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const b2 = `http://127.0.0.1:${srv.address().port}`;
  try {
    const mk = async (h) => {
      const c = new TelegraphClient({ server: b2, identity: TelegraphClient.generateIdentity() });
      await c.register({ handle: h });
      return c;
    };
    const a = await mk('u-a');
    await mk('u-b');
    const snap = async () => (await (await fetch(b2 + '/v1/admin/overview', { headers: { 'x-telegraph-admin': ADMIN } })).json()).metrics;

    await a.send('@u-b', 'this one is about to become unreadable');
    const before = await snap();
    assert.equal(before.wires.parked.wires, 1);
    assert.equal(before.wires.parked.unreadable, 0, 'nothing is wrong yet, and the field says so');
    assert.equal(before.wires.parked.dirUnreadable, false);

    // A well-formed file that is not a mailbox. This is one of the two ways a
    // mailbox can be unreadable, and it is the one that does NOT throw. The
    // other — a file that fails JSON.parse — used to 500 this entire route
    // before it could render the field being asserted below, which meant this
    // assertion passed on the only corruption shape that let it run. See the
    // truncated-file test underneath; both inputs now reach the census.
    const mdir = path.join(dir, 'mailboxes');
    const box = fs.readdirSync(mdir).find((f) => f.endsWith('.json') && !f.endsWith('.seen.json')
      && JSON.parse(fs.readFileSync(path.join(mdir, f), 'utf8')).length > 0);
    fs.writeFileSync(path.join(mdir, box), '{"not":"an array"}');

    const after = await snap();
    assert.equal(after.wires.parked.wires, 0, 'the wire is genuinely no longer countable');
    assert.equal(after.wires.parked.oldestAgeMs, null, 'and the age it was carrying went with it');
    // Without this the two lines above are byte-identical to a healthy, drained
    // relay. This is the whole difference between a reading and a renderer.
    assert.equal(after.wires.parked.unreadable, 1, 'so the failure has to appear somewhere');
  } finally {
    await new Promise((r) => srv.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The test above picked the one corruption shape that cannot throw. A truncated
// file — the shape an interrupted write or a full disk actually produces — threw
// out of Storage.loadMailbox inside the per-agent .map at the top of the same
// handler, so the response died before reaching the census that exists to report
// it. The detector's red branch was live in the suite and dead on the route: the
// operator got `internal_error`, which names no agent and looks like the service
// is down rather than like one file on disk is bad. This test is that input, at
// the route, because the route is the only thing an operator can call.
test('a truncated mailbox renders as unreadable instead of 500ing the whole overview', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-truncated-'));
  const srv = createServer({ dataDir: dir, adminToken: ADMIN, limits: { registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const b2 = `http://127.0.0.1:${srv.address().port}`;
  try {
    const mk = async (h) => {
      const c = new TelegraphClient({ server: b2, identity: TelegraphClient.generateIdentity() });
      await c.register({ handle: h });
      return c;
    };
    const a = await mk('t-a');
    await mk('t-b');
    await a.send('@t-b', 'this wire is about to become unparseable');

    const mdir = path.join(dir, 'mailboxes');
    const box = fs.readdirSync(mdir).find((f) => f.endsWith('.json') && !f.endsWith('.seen.json')
      && JSON.parse(fs.readFileSync(path.join(mdir, f), 'utf8')).length > 0);
    const raw = fs.readFileSync(path.join(mdir, box), 'utf8');
    fs.writeFileSync(path.join(mdir, box), raw.slice(0, Math.floor(raw.length / 2)));

    const res = await fetch(b2 + '/v1/admin/overview', { headers: { 'x-telegraph-admin': ADMIN } });
    assert.equal(res.status, 200, 'one bad file must not take down the operator view');
    const body = await res.json();
    assert.equal(body.metrics.wires.parked.unreadable, 1, 'the census has to survive to say so');

    // The count the operator reads per agent has to distinguish "could not look"
    // from "nothing there" — 0 would be the same flattering lie in a new place.
    const broken = body.agents.filter((x) => x.mailbox.unreadable);
    assert.equal(broken.length, 1, 'and it has to name which agent, which a 500 never could');
    assert.equal(broken[0].mailbox.count, null, 'not 0 — that would be the silent read all over again');
    assert.equal(broken[0].mailbox.oldestReceivedAt, null);
    assert.ok(body.agents.every((x) => x.mailbox.unreadable || typeof x.mailbox.count === 'number'),
      'the healthy mailboxes still report a real depth');
  } finally {
    await new Promise((r) => srv.close(r));
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
