import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

const ADMIN = 'test-admin-token';
let server;
let base;
let dataDir;
let alice;
let bob;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-admin-'));
  server = createServer({ dataDir, limits: { freeDailyTokens: 100 }, adminToken: ADMIN });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  alice = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  bob = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await alice.register({ handle: 'alice', bio: 'first' });
  await bob.register({ handle: 'bob' });
  await alice.send('@bob', 'wire-001'); // bob has queued mail, alice has spend
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

test('overview requires the admin token', async () => {
  const bare = await fetch(base + '/v1/admin/overview');
  assert.equal(bare.status, 403);
  const wrong = await fetch(base + '/v1/admin/overview', { headers: { 'x-telegraph-admin': 'nope' } });
  assert.equal(wrong.status, 403);
});

test('overview joins agents with billing and mailbox depth', async () => {
  const { status, body } = await adminFetch('/v1/admin/overview');
  assert.equal(status, 200);
  assert.equal(body.totals.agents, 2);
  assert.equal(body.limits.freeDailyTokens, 100);
  const byHandle = Object.fromEntries(body.agents.map((a) => [a.handle, a]));
  assert.equal(byHandle.alice.freeUsedToday, 2); // 8-char wire = 2 tokens
  assert.equal(byHandle.alice.mailbox.count, 0);
  assert.equal(byHandle.bob.mailbox.count, 1);
  assert.equal(byHandle.bob.credits, 0);
  assert.equal(body.totals.freeUsedToday, 2);
  assert.equal(body.totals.mailboxBacklog, 1);
  assert.deepEqual(body.payments, []);
});

test('remove drops the agent, its billing, and its mailbox', async () => {
  const bobAddress = bob.identity.address;
  const { status, body } = await adminFetch('/v1/admin/agents/remove', {
    method: 'POST',
    body: JSON.stringify({ address: bobAddress }),
  });
  assert.equal(status, 200);
  assert.equal(body.removed.handle, 'bob');
  assert.equal(body.droppedMailboxMessages, 1);

  const after = await adminFetch('/v1/admin/overview');
  assert.equal(after.body.totals.agents, 1);
  assert.equal(after.body.totals.mailboxBacklog, 0);
  assert.equal(fs.existsSync(path.join(dataDir, 'mailboxes', `${bobAddress}.json`)), false);
  const billing = JSON.parse(fs.readFileSync(path.join(dataDir, 'billing.json'), 'utf8'));
  assert.equal(billing[bobAddress], undefined);

  // Sending to a removed agent now fails; the handle is free to take again.
  await assert.rejects(() => alice.send('@bob', 'wire-002'), (e) => e.status === 404);
});

test('remove rejects handles and unknown addresses', async () => {
  const byHandle = await adminFetch('/v1/admin/agents/remove', {
    method: 'POST',
    body: JSON.stringify({ address: '@alice' }),
  });
  assert.equal(byHandle.status, 400);
  assert.equal(byHandle.body.error, 'bad_address');
  const unknown = await adminFetch('/v1/admin/agents/remove', {
    method: 'POST',
    body: JSON.stringify({ address: 'TG-0000-0000-0000-0000' }),
  });
  assert.equal(unknown.status, 404);
});

test('dashboard page is served without auth and contains no secrets', async () => {
  const res = await fetch(base + '/dashboard', { headers: { accept: 'text/html' } });
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /text\/html/);
  const html = await res.text();
  assert.match(html, /Operator dashboard/);
  assert.doesNotMatch(html, new RegExp(ADMIN));
});
