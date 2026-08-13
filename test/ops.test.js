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

// Every access row must be able to say WHEN. 39,545 rows written before this
// change carry no clock at all, which is why a claim sourced from them ("this
// gate was not firing across those fifteen days") could not be checked: the log
// can be ordered and cannot be dated, and the file mtime only knows the end.
test('every access log row carries a parseable timestamp of when it happened', async () => {
  const dataDir = tmpDir('logts');
  const lines = [];
  const server = createServer({ dataDir, logRequests: true, log: (l) => lines.push(l) });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  const before = Date.now();

  await fetch(`${base}/v1/health`);
  await fetch(`${base}/v1/directory`);
  await new Promise((r) => setTimeout(r, 20));

  // Access rows only — the same log sink also carries the attribution warning,
  // which is a JSON object and not a request record.
  const rows = lines.filter((l) => l.startsWith('[telegraph] '));
  assert.equal(rows.length, 2);
  for (const line of rows) {
    const m = /^\[telegraph\] (\d{4}-\d\d-\d\dT[\d:.]+Z) /.exec(line);
    assert.ok(m, `row must lead with an ISO timestamp: ${line}`);
    const t = Date.parse(m[1]);
    // Not merely "a string that looks like a date" — a date that lands in the
    // interval the request actually happened in. A hardcoded constant would
    // satisfy the shape and fail this.
    assert.ok(t >= before && t <= Date.now(), `timestamp ${m[1]} outside the request window`);
  }
  // The rest of the row is unchanged, so the existing parsers still see it.
  assert.ok(/GET \/v1\/health 200 \d+ms ua=/.test(rows[0]));

  await new Promise((r) => server.close(r));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

// The boot banner is the only non-request line in the log, so it is the only
// place a segment can record which settings produced it. health.trustProxy
// reports the value NOW; a log segment read next week needs the value THEN.
test('boot config publishes the settings that decide what a log segment means', async () => {
  const dataDir = tmpDir('bootcfg');
  const before = Date.now();
  const server = createServer({ dataDir, trustProxy: true, logRequests: true, attributionWindowMs: 1234 });
  const boot = server.telegraphBootConfig;

  assert.equal(boot.trustProxy, true, 'the setting whose past value the all-clear depended on');
  assert.equal(boot.logRequests, true);
  assert.equal(boot.attribution.windowMs, 1234, 'the injected window, not the default');
  assert.equal(typeof boot.attribution.indistinguishableAbove, 'number');
  assert.equal(typeof boot.attribution.partialAtOrAbove, 'number');
  assert.equal(typeof boot.attribution.partialMinObserved, 'number');
  const t = Date.parse(boot.startedAt);
  assert.ok(t >= before && t <= Date.now(), 'startedAt must date this boot');

  // The opposite setting must be reported as the opposite setting. Without this
  // arm, a banner hardcoding `trustProxy: true` passes the test above — which is
  // the exact failure being fixed: a field that cannot disagree.
  const off = createServer({ dataDir: tmpDir('bootcfg2') });
  assert.equal(off.telegraphBootConfig.trustProxy, false);
  assert.equal(off.telegraphBootConfig.logRequests, false);

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
