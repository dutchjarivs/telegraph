// Directory pagination: opt-in limit/offset with a stable oldest-first order,
// total count, and nextOffset cursor. No params = full listing, as before.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

const AGENTS = 7;

let server;
let base;
let dataDir;
let handles; // oldest-first registration order

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-directory-'));
  // registerRate raised: we register more identities than the anti-sybil default allows
  server = createServer({ dataDir, limits: { registerRate: { windowMs: 60_000, max: 100 } } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  handles = [];
  for (let i = 0; i < AGENTS; i++) {
    const c = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
    await c.register({ handle: `pager-${i}`, bio: i % 2 ? 'even keel' : 'odd duck' });
    handles.push(`pager-${i}`);
  }
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

const get = async (qs) => {
  const res = await fetch(`${base}/v1/directory${qs}`);
  return { status: res.status, body: await res.json() };
};

test('without pagination params the full directory returns, as before', async () => {
  const { status, body } = await get('');
  assert.equal(status, 200);
  assert.equal(body.count, AGENTS);
  assert.equal(body.total, AGENTS);
  assert.equal(body.agents.length, AGENTS);
  assert.ok(!('nextOffset' in body));
});

test('limit/offset page through the directory in stable order without gaps', async () => {
  // Expected order comes from the unpaged listing itself: same-ms
  // registrations tie-break by address, so registration order isn't guaranteed
  // — but the paged traversal must match the full listing exactly.
  const full = (await get('')).body.agents.map((a) => a.handle);
  const seen = [];
  let offset = 0;
  for (;;) {
    const { status, body } = await get(`?limit=3&offset=${offset}`);
    assert.equal(status, 200);
    assert.equal(body.total, AGENTS);
    assert.ok(body.count <= 3);
    seen.push(...body.agents.map((a) => a.handle));
    if (body.nextOffset === undefined) break;
    offset = body.nextOffset;
  }
  assert.deepEqual(seen, full); // every agent exactly once, in listing order
  assert.deepEqual([...seen].sort(), [...handles].sort()); // and nobody missing
});

test('q filtering composes with pagination and total reflects the filter', async () => {
  const { body } = await get('?q=odd%20duck&limit=2');
  assert.equal(body.total, Math.ceil(AGENTS / 2));
  assert.equal(body.count, 2);
  assert.ok(body.agents.every((a) => a.bio === 'odd duck'));
});

test('bad limit or offset is a clean 400', async () => {
  for (const qs of ['?limit=0', '?limit=-1', '?limit=1.5', '?limit=201', '?limit=abc']) {
    const { status, body } = await get(qs);
    assert.equal(status, 400, qs);
    assert.equal(body.error, 'bad_limit', qs);
  }
  for (const qs of ['?offset=-1', '?offset=2.5', '?offset=abc']) {
    const { status, body } = await get(qs);
    assert.equal(status, 400, qs);
    assert.equal(body.error, 'bad_offset', qs);
  }
});

test('an offset past the end returns an empty page, not an error', async () => {
  const { status, body } = await get(`?limit=5&offset=${AGENTS + 10}`);
  assert.equal(status, 200);
  assert.equal(body.count, 0);
  assert.equal(body.total, AGENTS);
  assert.ok(!('nextOffset' in body));
});

test('the client helper passes pagination through and reports total', async () => {
  const c = new TelegraphClient({ server: base });
  const page = await c.directory(undefined, { limit: 4 });
  assert.equal(page.agents.length, 4);
  assert.equal(page.total, AGENTS);
  assert.equal(page.nextOffset, 4);
  assert.ok(page.agents.every((a) => a.verified));
});
