// Regression tests for the security review fixes (2026-07-06):
//  1. prototype-chain keys can't bypass address/existence checks
//  2. duplicate suppression survives signature re-encoding
//  3. malformed input returns a clean 4xx, not a 500 with internal detail
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';
import { messageFields, signFields, encrypt } from '../src/crypto.js';

let server;
let base;
let dataDir;
let alice;
let bob;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-hardening-'));
  server = createServer({ dataDir, limits: { freeDailyTokens: 100_000 } });
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

const post = (p, body) =>
  fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

test('a wire addressed to a prototype key is rejected, not delivered', async () => {
  for (const target of ['__proto__', 'constructor', 'toString']) {
    const res = await post('/v1/messages', {
      to: target,
      from: alice.identity.address,
      nonce: 'x',
      ciphertext: 'x',
      ts: Date.now(),
      sig: 'x',
    });
    assert.equal(res.status, 400, `to=${target} should be 400`);
    assert.equal((await res.json()).error, 'bad_address');
  }
  // and none of those turned into junk mailbox files
  const files = fs.readdirSync(path.join(dataDir, 'mailboxes'));
  for (const junk of ['proto.json', 'constructor.json', 'toString.json']) {
    assert.ok(!files.includes(junk), `unexpected mailbox file ${junk}`);
  }
});

test('a prototype key in the auth address header does not bypass unknown_agent', async () => {
  const res = await fetch(base + '/v1/inbox', {
    headers: { 'x-telegraph-address': '__proto__', 'x-telegraph-ts': String(Date.now()), 'x-telegraph-sig': 'AAAA' },
  });
  assert.equal(res.status, 401);
});

test('duplicate suppression survives a re-encoded signature', async () => {
  const mts = Date.now();
  const { nonce, ciphertext } = encrypt('spam', bob.identity.boxPublicKey, alice.identity.boxSecretKey);
  const sig = signFields(
    messageFields(bob.identity.address, alice.identity.address, nonce, ciphertext, mts),
    alice.identity.signSecretKey,
  );
  const wire = { to: bob.identity.address, from: alice.identity.address, nonce, ciphertext, ts: mts, sig };

  const first = await (await post('/v1/messages', wire)).json();
  assert.equal(first.duplicate ?? false, false);

  // Same signature bytes, different base64 string (trailing space the decoder
  // ignores). Must be recognised as the same wire, not delivered twice.
  const second = await (await post('/v1/messages', { ...wire, sig: sig + ' ' })).json();
  assert.equal(second.duplicate, true);
  assert.equal(second.id, first.id);

  const inbox = await bob.inbox();
  const copies = inbox.filter((m) => m.id === first.id);
  assert.equal(copies.length, 1, 'exactly one copy should land in the mailbox');
});

test('malformed url encoding returns a clean 400, not a 500 with internal detail', async () => {
  const res = await fetch(base + '/v1/agents/%ZZ');
  assert.equal(res.status, 400);
  const body = await res.json();
  assert.equal(body.error, 'bad_request');
  assert.ok(!('detail' in body), 'must not leak internal error detail');
});

test('a valid-format but unregistered address still reads as unknown, not bad_address', async () => {
  // format check must not swallow the real "unknown sender" signal
  const { nonce, ciphertext } = encrypt('hi', bob.identity.boxPublicKey, alice.identity.boxSecretKey);
  const res = await post('/v1/messages', {
    to: bob.identity.address,
    from: 'TG-AAAA-BBBB-CCCC-DDDD', // well-formed, never registered
    nonce,
    ciphertext,
    ts: Date.now(),
    sig: 'AAAA',
  });
  assert.equal(res.status, 401);
  assert.equal((await res.json()).error, 'unknown_sender');
});

// --- Directory read limits, and the shared-bucket trap ----------------------
//
// The point of these: a per-IP limit is only a limit if the relay can actually
// tell clients apart. Behind a proxy that doesn't forward the client address,
// every request looks like it came from the proxy — and a limit keyed on that
// isn't a cap on one abuser, it's a bucket the entire userbase fills together.
// The first scraper would then take every legitimate agent down with them.
//
// So the relay skips the read limit in that state rather than enforcing a
// harmful one, and reports the misconfiguration. That fails open deliberately:
// these endpoints have no limit at all today, so skipping can't be worse than
// the status quo, while throttling everyone at once would be a self-inflicted
// outage. These tests pin that behaviour down so nobody "tightens" it later
// without understanding what they're turning on.

test('one IP hitting the cap does not throttle a different IP', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-lookup-iso-'));
  const server = createServer({
    dataDir,
    trustProxy: true,
    limits: { lookupRate: { windowMs: 60_000, max: 3 } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const read = (ip) => fetch(`${base}/v1/directory`, { headers: { 'x-forwarded-for': ip } });

    for (let i = 0; i < 3; i++) assert.equal((await read('203.0.113.7')).status, 200);
    assert.equal((await read('203.0.113.7')).status, 429, 'the scraper is capped');

    // The victim of a noisy neighbour must still be served. This is the whole
    // reason the limit is per-IP and not global.
    assert.equal((await read('198.51.100.4')).status, 200, 'an unrelated IP is unaffected');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('CF-Connecting-IP is preferred over X-Forwarded-For', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-lookup-cf-'));
  const server = createServer({
    dataDir,
    trustProxy: true,
    limits: { lookupRate: { windowMs: 60_000, max: 2 } },
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    // Cloudflare overwrites CF-Connecting-IP at the edge, so it can't be stuffed
    // with extra hops the way a client-supplied XFF chain can. A scraper that
    // rotates the XFF value must not get a fresh bucket each time.
    const read = (xff) => fetch(`${base}/v1/directory`, {
      headers: { 'cf-connecting-ip': '203.0.113.9', 'x-forwarded-for': xff },
    });
    assert.equal((await read('1.1.1.1')).status, 200);
    assert.equal((await read('2.2.2.2')).status, 200);
    assert.equal((await read('3.3.3.3')).status, 429, 'rotating XFF must not mint a new bucket');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('when the proxy hides the client IP, the read limit is skipped, not shared', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-lookup-blind-'));
  // trustProxy on, but (as if the proxy were misconfigured) no forwarding header
  // arrives — so every client collapses to loopback.
  const server = createServer({
    dataDir,
    trustProxy: true,
    adminToken: 'admin-tok',
    limits: { lookupRate: { windowMs: 60_000, max: 3 } },
    log: () => {}, // the relay warns loudly on stdout; not needed in the test output
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    // Far past the cap. If the relay were keying everyone into one loopback
    // bucket, request 4 would 429 — and in production that 429 would be served
    // to every agent on the relay at once.
    for (let i = 0; i < 10; i++) {
      assert.equal((await fetch(`${base}/v1/directory`)).status, 200, `read ${i + 1} must not be throttled`);
    }

    // But it must not be silent about it: a rate limit that isn't running has to
    // look different from one that is, or the operator believes they're covered.
    const overview = await (await fetch(`${base}/v1/admin/overview`, {
      headers: { 'x-telegraph-admin': 'admin-tok' },
    })).json();
    assert.equal(overview.health.clientIpsIndistinguishable, true);
    assert.match(overview.health.warning, /forward the client IP/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a spoofed X-Forwarded-For is ignored when the relay is not behind a proxy', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-lookup-spoof-'));
  // trustProxy defaults off. A directly-exposed relay must not let a client pick
  // its own rate-limit key by inventing a header.
  const server = createServer({ dataDir, limits: { lookupRate: { windowMs: 60_000, max: 3 } } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    // All of these come from the same socket. With trustProxy off the header is
    // ignored — but the socket address here IS loopback, so the limit is skipped
    // for the reason above. The property under test is that the *header* never
    // becomes the key: it must not be possible to mint buckets by rotating it.
    const responses = [];
    for (let i = 0; i < 8; i++) {
      responses.push((await fetch(`${base}/v1/directory`, {
        headers: { 'x-forwarded-for': `203.0.113.${i}` },
      })).status);
    }
    assert.ok(responses.every((s) => s === 200), 'loopback client: limit skipped, not keyed off a spoofable header');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a proxy on another host with trust off does not become one shared bucket', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-lookup-offhost-'));
  // The dangerous case, and the one a loopback check alone would miss. A proxy on
  // a *different* host has an ordinary LAN address, so with TELEGRAPH_TRUST_PROXY
  // off every request would key to that one address: a single bucket shared by
  // the entire userbase, where the first scraper 429s everybody.
  //
  // We can't fake a remote socket address in-process, so the property is tested
  // where it's decided: a forwarding header arriving while trustProxy is off is
  // proof we're behind a proxy we're ignoring, and must disable the per-IP limit.
  const server = createServer({
    dataDir,
    trustProxy: false, // the misconfiguration
    adminToken: 'admin-tok',
    limits: { lookupRate: { windowMs: 60_000, max: 3 } },
    log: () => {},
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    // Ten reads, all carrying a forwarding header the relay is not trusting.
    // Every one must be served: throttling here would be throttling everyone.
    for (let i = 0; i < 10; i++) {
      const res = await fetch(`${base}/v1/directory`, {
        headers: { 'x-forwarded-for': '203.0.113.20' },
      });
      assert.equal(res.status, 200, `read ${i + 1} must not be throttled on a shared bucket`);
    }

    const overview = await (await fetch(`${base}/v1/admin/overview`, {
      headers: { 'x-telegraph-admin': 'admin-tok' },
    })).json();
    assert.equal(overview.health.clientIpsIndistinguishable, true);
    assert.equal(overview.health.trustProxy, false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});
