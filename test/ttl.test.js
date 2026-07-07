// Mailbox TTL: with messageTtlMs set, unfetched wires older than the TTL are
// pruned lazily on every mailbox load — invisible to the inbox, and their slot
// in the mailbox cap frees up. Default (0) keeps wires forever.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

const TTL_MS = 60_000;

let server;
let base;
let dataDir;
let alice;
let bob;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-ttl-'));
  server = createServer({ dataDir, limits: { messageTtlMs: TTL_MS, mailboxCap: 2, freeDailyTokens: 100_000 } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  alice = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  bob = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await alice.register({ handle: 'alice' });
  await bob.register({ handle: 'bob' });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

// Age wires on disk instead of sleeping: rewrite receivedAt in the mailbox file.
function backdate(address, ids, byMs) {
  const file = path.join(dataDir, 'mailboxes', address.replace(/[^A-Za-z0-9-]/g, '') + '.json');
  const mailbox = JSON.parse(fs.readFileSync(file, 'utf8'));
  for (const m of mailbox) {
    if (ids.has(m.id)) m.receivedAt -= byMs;
  }
  fs.writeFileSync(file, JSON.stringify(mailbox));
}

test('an expired wire disappears from the inbox and is pruned on disk', async () => {
  const { id } = await alice.send('@bob', 'this one will age out');
  assert.equal((await bob.inbox()).length, 1);
  backdate(bob.identity.address, new Set([id]), TTL_MS + 1);
  assert.equal((await bob.inbox()).length, 0);
  // pruned from storage too, not just filtered from the response
  const file = path.join(dataDir, 'mailboxes', bob.identity.address + '.json');
  assert.equal(JSON.parse(fs.readFileSync(file, 'utf8')).length, 0);
});

test('only expired wires drop; fresh ones in the same mailbox survive', async () => {
  const old = await alice.send('@bob', 'old wire');
  const fresh = await alice.send('@bob', 'fresh wire');
  backdate(bob.identity.address, new Set([old.id]), TTL_MS + 1);
  const inbox = await bob.inbox();
  assert.equal(inbox.length, 1);
  assert.equal(inbox[0].id, fresh.id);
  await bob.ack([fresh.id]);
});

test('expiry frees mailbox-cap space for new deliveries', async () => {
  // cap is 2 — fill it
  const a = await alice.send('@bob', 'filler one');
  const b = await alice.send('@bob', 'filler two');
  await assert.rejects(() => alice.send('@bob', 'over cap'), /mailbox_full/);
  // age one out; the next wire must land instead of 507ing
  backdate(bob.identity.address, new Set([a.id]), TTL_MS + 1);
  const c = await alice.send('@bob', 'lands in the freed slot');
  const inbox = await bob.inbox();
  assert.deepEqual(inbox.map((m) => m.id).sort(), [b.id, c.id].sort());
  await bob.ack([b.id, c.id]);
});

test('with the default TTL of 0, wires never expire', async () => {
  const noTtlDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-nottl-'));
  const s = createServer({ dataDir: noTtlDir, limits: { freeDailyTokens: 100_000 } });
  await new Promise((resolve) => s.listen(0, '127.0.0.1', resolve));
  try {
    const b = `http://127.0.0.1:${s.address().port}`;
    const carol = new TelegraphClient({ server: b, identity: TelegraphClient.generateIdentity() });
    const dave = new TelegraphClient({ server: b, identity: TelegraphClient.generateIdentity() });
    await carol.register({ handle: 'carol' });
    await dave.register({ handle: 'dave' });
    const { id } = await carol.send('@dave', 'ancient but immortal');
    const file = path.join(noTtlDir, 'mailboxes', dave.identity.address + '.json');
    const mailbox = JSON.parse(fs.readFileSync(file, 'utf8'));
    mailbox[0].receivedAt -= 365 * 86_400_000; // a year old
    fs.writeFileSync(file, JSON.stringify(mailbox));
    const inbox = await dave.inbox();
    assert.equal(inbox.length, 1);
    assert.equal(inbox[0].id, id);
  } finally {
    await new Promise((resolve) => s.close(resolve));
    fs.rmSync(noTtlDir, { recursive: true, force: true });
  }
});

test('TELEGRAPH_MESSAGE_TTL_DAYS wires the TTL from the environment', async () => {
  process.env.TELEGRAPH_MESSAGE_TTL_DAYS = '30';
  try {
    const envDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-envttl-'));
    const s = createServer({ dataDir: envDir, adminToken: 'test-admin' });
    await new Promise((resolve) => s.listen(0, '127.0.0.1', resolve));
    try {
      const res = await fetch(`http://127.0.0.1:${s.address().port}/v1/admin/overview`, {
        headers: { 'x-telegraph-admin': 'test-admin' },
      });
      const body = await res.json();
      assert.equal(body.limits.messageTtlMs, 30 * 86_400_000);
    } finally {
      await new Promise((resolve) => s.close(resolve));
      fs.rmSync(envDir, { recursive: true, force: true });
    }
  } finally {
    delete process.env.TELEGRAPH_MESSAGE_TTL_DAYS;
  }
});
