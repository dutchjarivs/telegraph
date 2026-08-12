// Rate-limit bucket keying (2026-08-12).
//
// The per-IP limiters keyed on the exact client address. For IPv6 that is not a
// limit: a client is routinely handed a whole /64 and SLAAC privacy extensions
// rotate the host part on their own, so the "5 new identities per IP per hour"
// anti-sybil cap and the anonymous directory-read cap could both be reset by
// reconnecting. These tests pin the /64 collapse, and pin the trap that makes a
// naive collapse worse than the bug: IPv4-mapped addresses (::ffff:1.2.3.4) all
// share one IPv6 prefix, so folding them would put the whole IPv4 internet in a
// single shared bucket.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer, rateKeyForIp } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';
import { registerFields, signFields } from '../src/crypto.js';

test('IPv6 addresses in the same /64 share one bucket', () => {
  const a = rateKeyForIp('2603:90d8:201:c53:1111:2222:3333:4444');
  const b = rateKeyForIp('2603:90d8:201:c53:9999:8888:7777:6666');
  assert.equal(a, b);
  assert.equal(a, '2603:90d8:201:c53::/64');
});

test('a different /64 is a different bucket', () => {
  assert.notEqual(
    rateKeyForIp('2603:90d8:201:c53::1'),
    rateKeyForIp('2603:90d8:201:c54::1'),
  );
});

test('the :: shorthand expands before the prefix is taken', () => {
  // 2603:90d8::1 is 2603:90d8:0:0:...  — its /64 is NOT 2603:90d8:0:1.
  assert.equal(rateKeyForIp('2603:90d8::1'), '2603:90d8:0:0::/64');
  assert.equal(rateKeyForIp('2603:90d8:0:0:0:0:0:1'), '2603:90d8:0:0::/64');
  assert.equal(rateKeyForIp('::1'), '0:0:0:0::/64');
});

test('leading zeros and case do not split a bucket', () => {
  assert.equal(
    rateKeyForIp('2603:090d8'.replace('090d8', '90D8') + ':0201:0c53::1'),
    rateKeyForIp('2603:90d8:201:c53::2'),
  );
});

test('IPv4 keys on the exact address', () => {
  assert.equal(rateKeyForIp('203.0.113.7'), '203.0.113.7');
  assert.notEqual(rateKeyForIp('203.0.113.7'), rateKeyForIp('203.0.113.8'));
});

test('IPv4-mapped addresses key on the IPv4 address, not a shared prefix', () => {
  // The trap: ::ffff:203.0.113.7 and ::ffff:198.51.100.9 share the ::ffff:0:0
  // prefix. Collapsing them as IPv6 would throttle the entire IPv4 internet as
  // one client — a worse bug than the one being fixed.
  assert.equal(rateKeyForIp('::ffff:203.0.113.7'), '203.0.113.7');
  assert.notEqual(
    rateKeyForIp('::ffff:203.0.113.7'),
    rateKeyForIp('::ffff:198.51.100.9'),
  );
  assert.equal(rateKeyForIp('::ffff:203.0.113.7'), rateKeyForIp('203.0.113.7'));
});

test('a link-local zone id does not create a second bucket', () => {
  assert.equal(rateKeyForIp('fe80::1%eth0'), rateKeyForIp('fe80::2'));
});

test('junk and empty values get their own key, never a merged one', () => {
  assert.equal(rateKeyForIp('unknown'), 'unknown');
  assert.equal(rateKeyForIp(''), 'unknown');
  assert.equal(rateKeyForIp(undefined), 'unknown');
  // Unparseable but colon-bearing: keyed verbatim rather than folded together.
  assert.equal(rateKeyForIp('not:an:address'), 'not:an:address');
  assert.notEqual(rateKeyForIp('not:an:address'), rateKeyForIp('other:junk:x'));
});

// Register over raw HTTP so the test can choose the forwarded client address.
function registerFrom(base, sourceIp, handle) {
  const { signPublicKey, boxPublicKey, signSecretKey } = TelegraphClient.generateIdentity();
  const ts = Date.now();
  const sig = signFields(registerFields(handle, signPublicKey, boxPublicKey, '', [], ts), signSecretKey);
  return fetch(`${base}/v1/register`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': sourceIp },
    body: JSON.stringify({ handle, signPublicKey, boxPublicKey, bio: '', capabilities: [], ts, sig }),
  });
}

test('the registration cap holds when an IPv6 client rotates its host part', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-ratekey-'));
  const server = createServer({
    dataDir,
    trustProxy: true,
    limits: { registerRate: { windowMs: 60 * 60_000, max: 5 } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  // Every attempt is a fresh identity from a fresh address inside one /64 —
  // exactly what SLAAC privacy extensions hand a single machine for free.
  const statuses = [];
  for (let n = 1; n <= 7; n++) {
    const res = await registerFrom(base, `2001:db8:dead:beef::${n.toString(16)}`, `rot${n}`);
    statuses.push(res.status);
  }

  assert.deepEqual(statuses.slice(0, 5), [200, 200, 200, 200, 200]);
  assert.deepEqual(statuses.slice(5), [429, 429], 'rotating the host part must not buy a fresh bucket');
});

test('a genuinely different /64 still gets its own registration budget', async (t) => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-ratekey2-'));
  const server = createServer({
    dataDir,
    trustProxy: true,
    limits: { registerRate: { windowMs: 60 * 60_000, max: 2 } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  t.after(async () => {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  });

  assert.equal((await registerFrom(base, '2001:db8:1:1::1', 'n1')).status, 200);
  assert.equal((await registerFrom(base, '2001:db8:1:1::2', 'n2')).status, 200);
  assert.equal((await registerFrom(base, '2001:db8:1:1::3', 'n3')).status, 429);
  // Different network, unaffected — the collapse must not over-group.
  assert.equal((await registerFrom(base, '2001:db8:1:2::1', 'n4')).status, 200);
  // And distinct IPv4 clients stay distinct despite arriving IPv4-mapped.
  assert.equal((await registerFrom(base, '::ffff:203.0.113.7', 'n5')).status, 200);
  assert.equal((await registerFrom(base, '::ffff:198.51.100.9', 'n6')).status, 200);
});
