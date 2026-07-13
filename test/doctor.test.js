// telegraph doctor: setup diagnostics (relay, clock, identity, registration,
// balance) — and the preflight deploy check alongside it.
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
const PREFLIGHT = fileURLToPath(new URL('../scripts/preflight.js', import.meta.url));

let server;
let base;
let dataDir;
let workDir;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-doctor-'));
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-doctor-home-'));
  server = createServer({ dataDir });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
  fs.rmSync(workDir, { recursive: true, force: true });
});

// doctor exits 1 when checks fail, which execFile treats as an error — parse
// stdout either way.
async function doctor(env = {}) {
  try {
    const r = await exec(process.execPath, [CLI, 'doctor'], {
      cwd: workDir,
      env: { ...process.env, TELEGRAPH_SERVER: base, TELEGRAPH_IDENTITY: path.join(workDir, 'id.json'), ...env },
    });
    return { code: 0, ...JSON.parse(r.stdout) };
  } catch (err) {
    return { code: err.code, ...JSON.parse(err.stdout) };
  }
}

const check = (r, name) => r.checks.find((c) => c.name === name);

test('doctor with no identity: relay+clock pass, identity fails, exit 1', async () => {
  const r = await doctor();
  assert.equal(r.code, 1);
  assert.equal(r.ok, false);
  assert.equal(check(r, 'relay').ok, true);
  assert.equal(check(r, 'clock').ok, true);
  assert.equal(check(r, 'identity').ok, false);
  assert.match(check(r, 'identity').detail, /signup/);
});

test('doctor after signup: every check green, exit 0', async () => {
  await exec(process.execPath, [CLI, 'signup', '--handle', 'doc'], {
    cwd: workDir,
    env: { ...process.env, TELEGRAPH_SERVER: base, TELEGRAPH_IDENTITY: path.join(workDir, 'id.json') },
  });
  const r = await doctor();
  assert.equal(r.code, 0);
  assert.equal(r.ok, true);
  assert.match(check(r, 'registration').detail, /@doc/);
  assert.match(check(r, 'balance').detail, /free tokens/);
});

test('doctor with a keypair the relay does not know: registration fails', async () => {
  const freshHome = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-doctor-fresh-'));
  try {
    await exec(process.execPath, [CLI, 'keygen'], {
      cwd: freshHome,
      env: { ...process.env, TELEGRAPH_IDENTITY: path.join(freshHome, 'id.json') },
    });
    const r = await doctor({ TELEGRAPH_IDENTITY: path.join(freshHome, 'id.json') });
    assert.equal(r.code, 1);
    assert.equal(check(r, 'identity').ok, true);
    assert.equal(check(r, 'registration').ok, false);
    assert.match(check(r, 'registration').detail, /not registered/);
  } finally {
    fs.rmSync(freshHome, { recursive: true, force: true });
  }
});

test('doctor against a dead relay: relay check fails, exit 1', async () => {
  const r = await doctor({ TELEGRAPH_SERVER: 'http://127.0.0.1:1' });
  assert.equal(r.code, 1);
  assert.equal(check(r, 'relay').ok, false);
});

test('doctor tolerates clock skew under the ±5 min signing window', async () => {
  // A fake relay whose /v1/health reports a clock 90s ahead of local time.
  // Signed requests (authWindowMs = 5 min) would still succeed at that skew,
  // so doctor's clock check must not fail here.
  const http = await import('node:http');
  const fake = http.createServer((req, res) => {
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ ok: true, service: 'telegraph', release: 'fake', uptimeSeconds: 1, agents: 0, now: Date.now() + 90_000 }));
  });
  await new Promise((resolve) => fake.listen(0, '127.0.0.1', resolve));
  try {
    const r = await doctor({ TELEGRAPH_SERVER: `http://127.0.0.1:${fake.address().port}` });
    assert.equal(check(r, 'relay').ok, true);
    assert.equal(check(r, 'clock').ok, true);
    assert.match(check(r, 'clock').detail, /still under the ±5 min signing window/);
  } finally {
    await new Promise((resolve) => fake.close(resolve));
  }
});

test('npm run preflight passes on this box (warnings allowed, no failures)', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-preflight-home-'));
  try {
    const r = await exec(process.execPath, [PREFLIGHT], {
      cwd: home,
      // A .env-less home dir and a port nothing listens on: warnings only.
      env: { ...process.env, TELEGRAPH_PORT: '0' },
    });
    const body = JSON.parse(r.stdout);
    assert.equal(body.ok, true);
    assert.equal(body.checks.find((c) => c.name === 'smoke').level, 'ok');
    assert.ok(body.checks.every((c) => c.level !== 'fail'));
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
