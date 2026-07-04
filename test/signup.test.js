import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { createServer } from '../src/server.js';

const exec = promisify(execFile);
const CLI = fileURLToPath(new URL('../bin/telegraph.js', import.meta.url));

let server;
let base;
let dataDir;
let workDir;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-signup-'));
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-signup-home-'));
  server = createServer({ dataDir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(workDir, { recursive: true, force: true });
});

function cli(...args) {
  return exec(process.execPath, [CLI, ...args], {
    cwd: workDir,
    env: { ...process.env, TELEGRAPH_SERVER: base, TELEGRAPH_IDENTITY: path.join(workDir, 'id.json') },
  }).then((r) => JSON.parse(r.stdout));
}

test('GET /v1/onboard hands an agent everything needed to sign up', async () => {
  const o = await fetch(base + '/v1/onboard').then((r) => r.json());
  assert.equal(o.service, 'telegraph');
  assert.ok(Array.isArray(o.diy.steps) && o.diy.steps.length >= 5);
  assert.match(o.diy.steps.join(' '), /telegraph-register-v1/);
  assert.match(o.rules.registrationRateLimit, /\d+ new identities/);
  assert.match(o.rules.payment, /first paid top-up/);
});

test('signup goes from nothing to registered in one command', async () => {
  const r = await cli('signup', '--handle', 'newcomer', '--bio', 'born today', '--capabilities', 'testing');
  assert.equal(r.ok, true);
  assert.match(r.address, /^TG-/);
  assert.equal(r.handle, 'newcomer');
  assert.equal(r.identityCreated, true);
  assert.ok(r.freeRemainingToday > 0);
  assert.ok(fs.existsSync(path.join(workDir, 'id.json')));
});

test('the protocol spec is served by the relay, not just the repo', async () => {
  const res = await fetch(base + '/docs/PROTOCOL.md');
  assert.equal(res.status, 200);
  assert.match(res.headers.get('content-type'), /markdown/);
  const md = await res.text();
  assert.match(md, /telegraph-message-v1/);
  assert.match(md, /telegraph-auth-v1/);
  const readme = await fetch(base + '/README.md');
  assert.equal(readme.status, 200);
});

test('onboard documents the full wire format including message signing', async () => {
  const o = await fetch(base + '/v1/onboard').then((r) => r.json());
  const steps = o.sendingWires.steps.join(' ');
  assert.match(steps, /telegraph-message-v1/);
  assert.match(steps, /telegraph-auth-v1/);
  assert.match(steps, /e3b0c44298fc1c14/); // sha256 of empty string, for GET auth
});

test('an empty message body gets missing_fields, not too_long', async () => {
  const r = await fetch(base + '/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: '{}',
  });
  assert.equal(r.status, 400);
  const j = await r.json();
  assert.equal(j.error, 'missing_fields');
  assert.match(j.hint, /to, from, nonce, ciphertext, ts, sig/);
});

test('bad_signature errors state the exact canonical payload', async () => {
  const agent = await fetch(base + '/v1/directory').then((r) => r.json());
  const someone = agent.agents[0];
  const r = await fetch(base + '/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      to: someone.address,
      from: someone.address,
      nonce: Buffer.alloc(24).toString('base64'),
      ciphertext: Buffer.from('xx').toString('base64'),
      ts: Date.now(),
      sig: Buffer.alloc(64).toString('base64'),
    }),
  });
  assert.equal(r.status, 401);
  const j = await r.json();
  assert.equal(j.error, 'bad_signature');
  assert.match(j.hint, /telegraph-message-v1/);
});

test('signup is idempotent: rerunning reuses the identity and updates the record', async () => {
  const r = await cli('signup', '--handle', 'newcomer', '--bio', 'updated');
  assert.equal(r.ok, true);
  assert.equal(r.identityCreated, false);
  const dir = await fetch(base + '/v1/directory?q=newcomer').then((x) => x.json());
  assert.equal(dir.count, 1);
  assert.equal(dir.agents[0].bio, 'updated');
});
