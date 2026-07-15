// Operator audit trail: every admin-token mutation (grant, suspend, remove,
// report-resolve) leaves an append-only record — timestamp, action, source,
// and the relevant details — surfaced read-only in admin-overview and never
// containing the admin token itself. Hardening carry-over from the 2026-07-14
// grant incident: an operator action that moves credit or standing must be
// answerable after the fact ("who changed what, when, from where").
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

const ADMIN = 'audit-admin-token';
let server;
let base;
let dataDir;
let alice;
let bob;

function boot(dir) {
  return createServer({ dataDir: dir, limits: { freeDailyTokens: 100, registerRate: { windowMs: 60 * 60_000, max: 10_000 } }, adminToken: ADMIN });
}

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-audit-'));
  server = boot(dataDir);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
  alice = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  bob = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await alice.register({ handle: 'audit-alice' });
  await bob.register({ handle: 'audit-bob' });
});

test.after(async () => {
  await new Promise((r) => server.close(r));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

async function adminFetch(pathname, opts = {}) {
  const res = await fetch(base + pathname, {
    ...opts,
    headers: { 'x-telegraph-admin': ADMIN, 'content-type': 'application/json', ...(opts.headers ?? {}) },
  });
  return { status: res.status, body: await res.json() };
}

const overview = async () => (await adminFetch('/v1/admin/overview')).body;

test('a grant writes a credits.grant audit entry with amount and source', async () => {
  const before = (await overview()).auditTotal;
  const r = await adminFetch('/v1/credits/grant', { method: 'POST', body: JSON.stringify({ address: alice.identity.address, tokens: 5000 }) });
  assert.equal(r.status, 200);
  const ov = await overview();
  assert.equal(ov.auditTotal, before + 1);
  const entry = ov.audit[0]; // newest first
  assert.equal(entry.action, 'credits.grant');
  assert.equal(entry.address, alice.identity.address);
  assert.equal(entry.tokens, 5000);
  assert.equal(entry.actor, 'admin');
  assert.ok(typeof entry.at === 'number' && entry.at > 0);
  assert.ok('sourceIp' in entry); // captured (may be an IP or null behind a proxy)
});

test('a suspension is audited too', async () => {
  await adminFetch('/v1/admin/agents/suspend', { method: 'POST', body: JSON.stringify({ address: bob.identity.address, suspended: true, note: 'testing' }) });
  const ov = await overview();
  const suspendEntry = ov.audit.find((e) => e.action === 'agent.suspend' && e.address === bob.identity.address);
  assert.ok(suspendEntry, 'suspend recorded');
  assert.equal(suspendEntry.suspended, true);
});

test('remove is audited, and the entry survives the agent it describes', async () => {
  const doomed = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await doomed.register({ handle: 'audit-doomed' });
  await adminFetch('/v1/admin/agents/remove', { method: 'POST', body: JSON.stringify({ address: doomed.identity.address }) });
  const ov = await overview();
  const entry = ov.audit.find((e) => e.action === 'agent.remove' && e.address === doomed.identity.address);
  assert.ok(entry, 'remove recorded');
  assert.equal(entry.handle, 'audit-doomed');
  // The agent is gone from the directory, but the audit record remains.
  assert.equal(ov.agents.some((a) => a.address === doomed.identity.address), false);
});

test('the audit trail never contains the admin token', async () => {
  const ov = await overview();
  const serialized = JSON.stringify(ov.audit);
  assert.equal(serialized.includes(ADMIN), false);
});

test('the audit trail persists across a relay restart', async () => {
  const beforeTotal = (await overview()).auditTotal;
  await new Promise((r) => server.close(r));
  server = boot(dataDir);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
  const ov = await overview();
  assert.equal(ov.auditTotal, beforeTotal, 'audit count is unchanged after restart');
  assert.ok(ov.audit.length > 0, 'entries reload from disk');
});
