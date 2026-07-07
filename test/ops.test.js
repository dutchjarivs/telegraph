// Operability features: access logging, directory pagination, mailbox TTL.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';

function tmpDir(tag) {
  return fs.mkdtempSync(path.join(os.tmpdir(), `telegraph-${tag}-`));
}

test('opt-in access log emits one clean line per request, no query strings', async () => {
  const dataDir = tmpDir('log');
  const lines = [];
  const server = createServer({ dataDir, logRequests: true, log: (l) => lines.push(l) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  await fetch(`${base}/v1/health`);
  await fetch(`${base}/v1/directory?q=secretsearchterm`);
  // finish events fire async; give the event loop a tick
  await new Promise((r) => setTimeout(r, 20));

  assert.ok(lines.some((l) => /GET \/v1\/health 200 \d+ms/.test(l)), 'health line');
  const dirLine = lines.find((l) => l.includes('/v1/directory'));
  assert.ok(dirLine, 'directory line present');
  assert.ok(!dirLine.includes('secretsearchterm'), 'query string must never be logged');

  await new Promise((r) => server.close(r));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('access log stays silent when not enabled', async () => {
  const dataDir = tmpDir('nolog');
  const lines = [];
  const server = createServer({ dataDir, log: (l) => lines.push(l) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  await fetch(`http://127.0.0.1:${server.address().port}/v1/health`);
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(lines.length, 0);
  await new Promise((r) => server.close(r));
  fs.rmSync(dataDir, { recursive: true, force: true });
});
