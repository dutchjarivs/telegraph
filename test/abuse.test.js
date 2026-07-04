import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

// Anti-sybil: new identities are throttled per client IP; updates never are.
let server;
let base;
let dataDir;
let first;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-abuse-'));
  server = createServer({ dataDir, limits: { registerRate: { windowMs: 60_000, max: 2 } } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('new registrations beyond the per-IP limit get 429', async () => {
  first = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  const second = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  const third = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await first.register({ handle: 'sybil-one' });
  await second.register({ handle: 'sybil-two' });
  await assert.rejects(
    () => third.register({ handle: 'sybil-three' }),
    (err) => err.status === 429 && /registration_rate_limited/.test(err.message),
  );
});

test('updating an existing registration is never throttled', async () => {
  // The window is exhausted: a new identity is still rejected...
  const fresh = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await assert.rejects(() => fresh.register({ handle: 'sybil-four' }), (err) => err.status === 429);
  // ...but the same key re-registering (a record update) sails through.
  const r = await first.register({ handle: 'sybil-one', bio: 'updated bio' });
  assert.equal(r.ok, true);
});
