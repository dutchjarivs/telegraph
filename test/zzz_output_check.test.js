import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

// Directory reads are now rate-limited per IP. This test was a `skip` marking the
// gap: GET /v1/directory and GET /v1/agents/:x are the only endpoints an
// anonymous stranger can hit at will, and without a cap the entire directory —
// every address, public key and bio — can be harvested in a loop and turned into
// a spam target list. Now implemented; the skip is replaced with real coverage.
// The trust-proxy and shared-bucket cases live in test/hardening.test.js.

test('directory reads are rate-limited per IP', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-lookuprate-'));
  // trustProxy + an XFF header is how a test says "this request came from a real
  // remote client". Without it every request originates from 127.0.0.1, which the
  // relay treats as an indistinguishable client and deliberately does not throttle
  // (see the shared-bucket tests in hardening.test.js).
  const server = createServer({
    dataDir,
    trustProxy: true,
    limits: { lookupRate: { windowMs: 60_000, max: 5 } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const scraper = { 'x-forwarded-for': '203.0.113.50' };
  try {
    const agent = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
    await agent.register({ handle: 'scrape-me' });

    // Five reads are fine; the sixth is refused.
    for (let i = 0; i < 5; i++) {
      const ok = await fetch(`${base}/v1/agents/@scrape-me`, { headers: scraper });
      assert.equal(ok.status, 200, `read ${i + 1} should pass`);
    }
    const blocked = await fetch(`${base}/v1/agents/@scrape-me`, { headers: scraper });
    assert.equal(blocked.status, 429);
    assert.equal((await blocked.json()).error, 'rate_limited');
    // An honest client in a loop needs to be told when to come back, or it can't
    // back off — and then it looks exactly like the scraper we're trying to stop.
    assert.equal(blocked.headers.get('retry-after'), '60');

    // The whole-directory endpoint shares the budget: enumerating via
    // /v1/directory instead of one-by-one must not be a way around the cap.
    assert.equal((await fetch(`${base}/v1/directory`, { headers: scraper })).status, 429);

    // Health is not part of the scraping surface and must stay up — it's what a
    // monitor polls, and throttling your own uptime check is a fine way to get
    // paged at 4am for an outage that isn't happening.
    assert.equal((await fetch(`${base}/v1/health`, { headers: scraper })).status, 200);

    // And the capped scraper has not affected anybody else.
    assert.equal((await fetch(`${base}/v1/directory`, {
      headers: { 'x-forwarded-for': '198.51.100.77' },
    })).status, 200, 'a different agent is still served');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

// Phase 2: admin overview should not leak secret config values

test('admin overview does not include the admin token or stripe secret', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-harden-'));
  const server = createServer({
    dataDir,
    adminToken: 'super-secret-token-123',
    stripeWebhookSecret: 'whsec_testsecret',
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  const res = await fetch(base + '/v1/admin/overview', {
    headers: { 'x-telegraph-admin': 'super-secret-token-123' },
  });
  const body = await res.json();
  const flat = JSON.stringify(body);

  assert.ok(!flat.includes('super-secret-token-123'), 'admin token must not appear in overview');
  assert.ok(!flat.includes('whsec_testsecret'), 'stripe secret must not appear in overview');
  assert.ok(!flat.includes('whsec_'), 'no whsec_ prefix should appear anywhere');

  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

// Phase 2: health endpoint should not leak internal paths or config

test('health endpoint exposes only safe public fields', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-health-'));
  const server = createServer({
    dataDir,
    adminToken: 'secret-admin-tok',
    stripeWebhookSecret: 'whsec_secret',
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  const res = await fetch(base + '/v1/health');
  const body = await res.json();
  const flat = JSON.stringify(body);

  assert.ok(!flat.includes('secret-admin-tok'), 'admin token must not leak in health');
  assert.ok(!flat.includes('whsec_'), 'stripe secret must not leak in health');
  assert.ok(!flat.includes('dataDir'), 'internal paths must not leak in health');
  assert.equal(body.ok, true);
  assert.equal(typeof body.agents, 'number');

  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

// Phase 2: no-such-route response should not include internal file paths

test('no-such-route response has no file paths or stack traces', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-noroute-'));
  const server = createServer({ dataDir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  const res = await fetch(base + '/v1/nonexistent');
  const body = await res.json();
  const flat = JSON.stringify(body);

  assert.equal(res.status, 404);
  assert.ok(!flat.includes('C:\\'), 'no Windows paths in response');
  assert.ok(!flat.includes('/home/'), 'no Unix paths in response');
  assert.ok(!flat.includes('.js'), 'no source file references in response');
  assert.ok(Array.isArray(body.routes), 'should list available routes');

  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

// Phase 2: register with empty handle gives clean error

test('register with empty string handle is rejected cleanly', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-empty-'));
  const server = createServer({ dataDir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;

  const res = await fetch(base + '/v1/register', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      handle: '',
      signPublicKey: 'x',
      boxPublicKey: 'x',
      bio: '',
      capabilities: [],
      ts: Date.now(),
      sig: 'x',
    }),
  });
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, 'bad_handle');

  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});