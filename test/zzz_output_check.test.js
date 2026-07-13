import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

// Phase 2 hardening: rate limit gap — directory lookup has no rate limit.
// A malicious agent could hammer GET /v1/agents/@handle to enumerate the
// entire directory or DoS the relay. This test documents the current
// behavior (no limit) so we know to add one.

test.skip('directory lookup should be rate-limited per IP', async () => {
  // Skipped: rate limiting on GET /v1/agents/{x} is not yet implemented.
  // This is a hardening gap, not a regression.
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