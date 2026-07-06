import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

// Spam/scam reporting: reports carry cryptographic proof of a received wire,
// enough distinct reporters flags the sender publicly, and the operator can
// reversibly suspend. The relay never needs to read a single wire for any of it.
const ADMIN = 'reports-admin-token';
let server;
let base;
let dataDir;
let scammer;
let victim1;
let victim2;
let victim3;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-reports-'));
  server = createServer({
    dataDir,
    adminToken: ADMIN,
    limits: { registerRate: { windowMs: 60_000, max: 20 } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  scammer = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  victim1 = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  victim2 = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  victim3 = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await scammer.register({ handle: 'definitely-legit', bio: 'send me your keys' });
  await victim1.register({ handle: 'victim-one' });
  await victim2.register({ handle: 'victim-two' });
  await victim3.register({ handle: 'victim-three' });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

async function adminFetch(pathname, opts = {}) {
  const res = await fetch(base + pathname, {
    ...opts,
    headers: { 'x-telegraph-admin': ADMIN, 'content-type': 'application/json', ...(opts.headers ?? {}) },
  });
  return { status: res.status, body: await res.json() };
}

test('a wire still in the mailbox can be reported by messageId', async () => {
  await scammer.send('@victim-one', 'urgent: wire me 500 USDC and I will return 1000');
  const [wire] = await victim1.inbox(); // no ack — still in the mailbox
  const r = await victim1.report(wire.id, { reason: 'scam', comment: 'advance-fee scam' });
  assert.equal(r.ok, true);
  assert.equal(r.reported, scammer.identity.address);
  assert.equal(r.standing.distinctReporters, 1);
  assert.equal(r.standing.flagged, false);
});

test('re-reporting the same wire is acknowledged, not double-counted', async () => {
  const [wire] = await victim1.inbox();
  const r = await victim1.report(wire.id, { reason: 'scam' });
  assert.equal(r.duplicate, true);
  assert.equal(r.standing.distinctReporters, 1);
});

test('an acked wire can still be reported with its signed envelope', async () => {
  await scammer.send('@victim-two', 'you have won a prize, claim at evil.example');
  const [wire] = await victim2.inbox({ ack: true }); // gone from the mailbox now
  const r = await victim2.report(wire, { reason: 'phishing' });
  assert.equal(r.ok, true);
  assert.equal(r.standing.distinctReporters, 2);
  // ...but a bare messageId no longer works after ack.
  await assert.rejects(
    () => victim2.report(wire.id, { reason: 'phishing' }),
    (e) => e.status === 404 && /message_not_found/.test(e.message),
  );
});

test('reports validate reason, evidence, and ownership', async () => {
  const [wire] = await victim1.inbox();
  // unknown reason
  await assert.rejects(() => victim1.report(wire.id, { reason: 'annoying' }), (e) => e.status === 400);
  // no evidence at all
  const res = await fetch(base + '/v1/reports', { method: 'POST', body: '{}' });
  assert.equal(res.status, 401); // unsigned requests never get in
  // reporting someone else's wire: victim3 replays victim1's envelope
  await assert.rejects(
    () => victim3.report(wire.envelope, { reason: 'scam' }),
    (e) => e.status === 403 && /not_your_wire/.test(e.message),
  );
  // a tampered envelope fails signature verification
  const forged = { ...wire.envelope, ciphertext: Buffer.from('forged!').toString('base64') };
  await assert.rejects(
    () => victim1.report(forged, { reason: 'scam' }),
    (e) => e.status === 400 && /bad_evidence/.test(e.message),
  );
});

test('you cannot report your own wire', async () => {
  await victim1.send('@victim-one', 'note to self');
  const mine = (await victim1.inbox()).find((m) => m.from === victim1.identity.address);
  await assert.rejects(
    () => victim1.report(mine.id, { reason: 'spam' }),
    (e) => e.status === 400 && /cannot_report_self/.test(e.message),
  );
});

test('enough distinct reporters flags the agent everywhere public', async () => {
  // Before the third reporter: not flagged.
  let dir = await victim1.directory('legit');
  assert.equal(dir.agents[0].flagged, undefined);
  // Third distinct reporter crosses the default threshold (3).
  await scammer.send('@victim-three', 'act now, limited slots');
  const [wire] = await victim3.inbox();
  const r = await victim3.report(wire.id, { reason: 'spam' });
  assert.equal(r.standing.flagged, true);
  // Directory, lookup, and inbox sender records all warn.
  dir = await victim1.directory('legit');
  assert.equal(dir.agents[0].flagged, true);
  assert.match(dir.agents[0].flagWarning, /reported/);
  assert.equal(dir.agents[0].verified, true); // extra fields never break record verification
  const looked = await victim1.lookup('@definitely-legit');
  assert.equal(looked.flagged, true);
  const inboxNow = await victim3.inbox();
  assert.equal(inboxNow.find((m) => m.from === scammer.identity.address).flagged, true);
});

test('reports/mine shows what you filed and its status', async () => {
  const mine = await victim1.myReports();
  assert.equal(mine.count, 1);
  assert.equal(mine.reports[0].reported, scammer.identity.address);
  assert.equal(mine.reports[0].reportedHandle, 'definitely-legit');
  assert.equal(mine.reports[0].status, 'open');
});

test('admin sees all reports; dismissing drops them from the flag count', async () => {
  const all = await adminFetch('/v1/admin/reports');
  assert.equal(all.status, 200);
  assert.equal(all.body.count, 3);
  assert.equal(all.body.open, 3);
  assert.equal(all.body.reports[0].reportedHandle, 'definitely-legit');
  assert.equal(all.body.reports[0].reportedStanding.flagged, true);

  // Dismiss one report → distinct reporters falls to 2 → flag clears.
  const target = all.body.reports.find((r) => r.reporter === victim1.identity.address);
  const resolved = await adminFetch('/v1/admin/reports/resolve', {
    method: 'POST',
    body: JSON.stringify({ id: target.id, resolution: 'dismissed', note: 'looked legit on review' }),
  });
  assert.equal(resolved.status, 200);
  assert.equal(resolved.body.standing.flagged, false);
  const dir = await victim1.directory('legit');
  assert.equal(dir.agents[0].flagged, undefined);

  // Marking it actioned counts again — flag returns.
  const reactioned = await adminFetch('/v1/admin/reports/resolve', {
    method: 'POST',
    body: JSON.stringify({ id: target.id, resolution: 'actioned' }),
  });
  assert.equal(reactioned.body.standing.flagged, true);

  // Bad resolution and unknown ids are rejected.
  const bad = await adminFetch('/v1/admin/reports/resolve', {
    method: 'POST',
    body: JSON.stringify({ id: target.id, resolution: 'shrug' }),
  });
  assert.equal(bad.status, 400);
  const missing = await adminFetch('/v1/admin/reports/resolve', {
    method: 'POST',
    body: JSON.stringify({ id: 'ffffffffffffffffffffffff', resolution: 'dismissed' }),
  });
  assert.equal(missing.status, 404);
});

test('suspension blocks sending, delists, and is reversible', async () => {
  const address = scammer.identity.address;
  const sus = await adminFetch('/v1/admin/agents/suspend', {
    method: 'POST',
    body: JSON.stringify({ address, suspended: true, note: 'three verified scam reports' }),
  });
  assert.equal(sus.status, 200);
  assert.equal(sus.body.suspended, true);

  // Sending is blocked with a clear error...
  await assert.rejects(
    () => scammer.send('@victim-one', 'one more chance?'),
    (e) => e.status === 403 && /sender_suspended/.test(e.message),
  );
  // ...the agent disappears from discovery...
  const dir = await victim1.directory();
  assert.equal(dir.agents.some((a) => a.address === address), false);
  // ...but direct lookup still resolves, labelled, so correspondents can see why.
  const looked = await victim1.lookup(address);
  assert.equal(looked.suspended, true);
  // Receiving and reading still work: suspension is not a mailbox death sentence.
  await victim1.send(address, 'we know what you did');
  const inbox = await scammer.inbox();
  assert.equal(inbox.some((m) => m.text === 'we know what you did'), true);

  // Reversible: unsuspend and the agent can send and be found again.
  await adminFetch('/v1/admin/agents/suspend', {
    method: 'POST',
    body: JSON.stringify({ address, suspended: false }),
  });
  const sent = await scammer.send('@victim-one', 'reformed, honest');
  assert.equal(typeof sent.id, 'string');
  const dirAfter = await victim1.directory();
  assert.equal(dirAfter.agents.some((a) => a.address === address), true);
});

test('suspension survives re-registration — same key, same sentence', async () => {
  const address = scammer.identity.address;
  await adminFetch('/v1/admin/agents/suspend', {
    method: 'POST',
    body: JSON.stringify({ address, suspended: true }),
  });
  await scammer.register({ handle: 'definitely-legit', bio: 'fresh start, promise' });
  await assert.rejects(() => scammer.send('@victim-one', 'hello again'), (e) => e.status === 403);
  await adminFetch('/v1/admin/agents/suspend', {
    method: 'POST',
    body: JSON.stringify({ address, suspended: false }),
  });
});

test('moderation endpoints require the admin token', async () => {
  const noToken = await fetch(base + '/v1/admin/reports');
  assert.equal(noToken.status, 403);
  const wrong = await fetch(base + '/v1/admin/agents/suspend', {
    method: 'POST',
    headers: { 'x-telegraph-admin': 'nope', 'content-type': 'application/json' },
    body: JSON.stringify({ address: scammer.identity.address, suspended: true }),
  });
  assert.equal(wrong.status, 403);
});

test('reports are rate-limited per reporter', async () => {
  // Separate relay with a tight limit so this can't interfere with the tests above.
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-reportrate-'));
  const server2 = createServer({ dataDir: dir2, limits: { reportRate: { windowMs: 60_000, max: 1 } } });
  await new Promise((resolve) => server2.listen(0, '127.0.0.1', resolve));
  const base2 = `http://127.0.0.1:${server2.address().port}`;
  try {
    const spammy = new TelegraphClient({ server: base2, identity: TelegraphClient.generateIdentity() });
    const marks = new TelegraphClient({ server: base2, identity: TelegraphClient.generateIdentity() });
    await spammy.register({ handle: 'spammy' });
    await marks.register({ handle: 'marks' });
    await spammy.send('@marks', 'buy now 1');
    await spammy.send('@marks', 'buy now 2');
    const wires = await marks.inbox();
    assert.equal(wires.length, 2);
    await marks.report(wires[0].id, { reason: 'spam' });
    await assert.rejects(
      () => marks.report(wires[1].id, { reason: 'spam' }),
      (e) => e.status === 429 && /report_rate_limited/.test(e.message),
    );
  } finally {
    await new Promise((resolve) => server2.close(resolve));
    fs.rmSync(dir2, { recursive: true, force: true });
  }
});

test('admin overview carries moderation standing for the dashboard', async () => {
  const { body } = await adminFetch('/v1/admin/overview');
  assert.equal(body.totals.reports.total, 3);
  assert.equal(body.totals.reports.flaggedAgents, 1);
  assert.equal(body.totals.reports.suspendedAgents, 0);
  const row = body.agents.find((a) => a.address === scammer.identity.address);
  assert.equal(row.reports.flagged, true);
  assert.equal(row.reports.distinctReporters, 3);
  assert.equal(row.suspended, false);
  assert.equal(body.reports.length, 3);
  assert.equal(body.reports[0].reportedHandle, 'definitely-legit');
});
