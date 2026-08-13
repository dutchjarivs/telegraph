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
    assert.match(overview.health.warning, /not forwarding the client IP/);
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

// The degradation signal has to be able to turn back off.
//
// Found in production: the relay reported clientIpsIndistinguishable: true with
// "fix the proxy to forward the client IP" while the proxy was forwarding
// perfectly and public reads were being limited normally. The flag latched on
// the first request that happened to be unattributable — a loopback smoke test
// against the relay's own port, seconds after boot — and nothing ever cleared
// it. A bit that is always 1 and a bit that is correctly 1 look identical on a
// dashboard, so the operator learns nothing from either.
//
// Local traffic is not evidence of a broken proxy. The discriminating fact is
// whether any request ever resolves to a distinct client.
test('local pokes do not make the relay report broken client attribution', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-attribution-'));
  const server = createServer({
    dataDir,
    trustProxy: true, // behind a proxy that does forward the client address
    adminToken: 'admin-tok',
    limits: { lookupRate: { windowMs: 60_000, max: 3 } },
    log: () => {},
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const overview = async () => (await fetch(`${base}/v1/admin/overview`, {
    headers: { 'x-telegraph-admin': 'admin-tok' },
  })).json();
  try {
    // The smoke test that used to poison the flag for the process lifetime.
    assert.equal((await fetch(`${base}/v1/directory`)).status, 200);
    assert.equal((await overview()).health.clientIpsIndistinguishable, true,
      'with nothing but loopback seen, saying so is correct');

    // Now a real client arrives through the proxy. One is enough to prove the
    // relay can tell clients apart.
    assert.equal((await fetch(`${base}/v1/directory`, {
      headers: { 'cf-connecting-ip': '203.0.113.7' },
    })).status, 200);

    const after = await overview();
    assert.equal(after.health.clientIpsIndistinguishable, false,
      'a loopback poke must not outweigh a genuine client');
    assert.equal(after.health.warning, undefined, 'no warning when nothing is wrong');
    assert.equal(after.health.clientAttribution.loopback, 1);
    assert.equal(after.health.clientAttribution.distinct, 1);

    // And the limit the old flag claimed was being skipped is in fact enforced:
    // cap is 3, and this client has spent 1 of them.
    for (const expected of [200, 200, 429]) {
      const res = await fetch(`${base}/v1/directory`, {
        headers: { 'cf-connecting-ip': '203.0.113.7' },
      });
      assert.equal(res.status, expected);
    }

    // A different client is unaffected — the bucket is per-network, not shared.
    assert.equal((await fetch(`${base}/v1/directory`, {
      headers: { 'cf-connecting-ip': '198.51.100.9' },
    })).status, 200);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

// ...and it has to be able to turn back ON, which the first fix got wrong.
//
// Raised publicly by another agent reading the repair: the obvious predicate
// `sawUnattributable && distinct === 0` swaps a latch that can never go green
// for one that can never go red again. `distinct` only ever increases, so the
// first genuine client silences the check for the life of the process — and a
// proxy that regresses later, with thousands of good reads banked, leaves it
// false forever. A false red is loud and gets fixed. A false green has nobody
// to file against it.
//
// So the verdict is a window question, and this is the edge that proves it.
test('a proxy that regresses after real traffic is reported again', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-attribution-regress-'));
  const server = createServer({
    dataDir,
    trustProxy: true,
    adminToken: 'admin-tok',
    attributionWindowMs: 150, // an hour is the default; this is the same edge, sooner
    limits: { lookupRate: { windowMs: 60_000, max: 100 } },
    log: () => {},
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const health = async () => (await (await fetch(`${base}/v1/admin/overview`, {
    headers: { 'x-telegraph-admin': 'admin-tok' },
  })).json()).health;
  try {
    // Bank a pile of genuine, distinctly-attributed reads — the state in which
    // the previous predicate became permanently, silently false.
    for (let i = 0; i < 25; i += 1) {
      assert.equal((await fetch(`${base}/v1/directory`, {
        headers: { 'cf-connecting-ip': `203.0.113.${i + 1}` },
      })).status, 200);
    }
    const banked = await health();
    assert.equal(banked.clientIpsIndistinguishable, false);
    assert.equal(banked.clientAttribution.distinct, 25);

    // The proxy stops forwarding. Every client now collapses to loopback.
    await new Promise((resolve) => setTimeout(resolve, 200));
    assert.equal((await fetch(`${base}/v1/directory`)).status, 200);

    const regressed = await health();
    assert.equal(regressed.clientIpsIndistinguishable, true,
      '25 distinct clients an hour ago must not vouch for the proxy now');
    assert.match(regressed.warning, /loopback/);
    // The counts that outvoted the truth in the old predicate are still there,
    // and still all-time — the operator reads them beside a recency, not
    // instead of one.
    assert.equal(regressed.clientAttribution.distinct, 25);
    assert.ok(regressed.clientAttribution.lastDistinctAgoMs > 150);
    assert.ok(regressed.clientAttribution.lastUnattributableAgoMs < 150);

    // And it still clears on one real client, as it did before.
    assert.equal((await fetch(`${base}/v1/directory`, {
      headers: { 'cf-connecting-ip': '198.51.100.9' },
    })).status, 200);
    assert.equal((await health()).clientIpsIndistinguishable, false);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

// A relay nobody is talking to is not a relay with a broken proxy. With no
// traffic in the window at all the flag makes no claim, because it has seen
// nothing to make one about — and it re-fires the moment traffic returns.
test('attribution verdict makes no claim about a window with no traffic', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-attribution-quiet-'));
  const server = createServer({
    dataDir,
    trustProxy: true,
    adminToken: 'admin-tok',
    attributionWindowMs: 150,
    log: () => {},
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const health = async () => (await (await fetch(`${base}/v1/admin/overview`, {
    headers: { 'x-telegraph-admin': 'admin-tok' },
  })).json()).health;
  try {
    assert.equal((await fetch(`${base}/v1/directory`)).status, 200);
    assert.equal((await health()).clientIpsIndistinguishable, true,
      'loopback and nothing else is a true thing to say while it is happening');

    await new Promise((resolve) => setTimeout(resolve, 200));
    const quiet = await health();
    assert.equal(quiet.clientIpsIndistinguishable, false,
      'nothing observed in the window means nothing to report, not a fault');
    assert.equal(quiet.warning, undefined);

    assert.equal((await fetch(`${base}/v1/directory`)).status, 200);
    assert.equal((await health()).clientIpsIndistinguishable, true,
      'and it comes straight back when the traffic does');
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

// The third instance of the same bug, in the fix for the second.
//
// Raised publicly, again from the commit message alone: replacing "has a
// distinct client ever been seen" with "has one been seen lately" swaps a latch
// for a decay and keeps the quantifier. `sawUnattributable && !sawDistinct` is
// still existential, so ONE distinct request anywhere in the window — a health
// check from a real address, every few minutes, forever — reports the relay
// healthy while any amount of traffic beside it collapses to a single bucket.
//
// And that is the likely failure, not the exotic one. Total proxy death is loud.
// A second ingress that doesn't forward, or one listener of two misconfigured,
// leaves both signals live in the same window permanently: the verdict is not
// stuck, it is correct by its own definition and still wrong.
//
// Neither of the two tests above can construct that state — each moves through
// windows in which exactly one signal is live, which is why they passed. This
// one puts both in the same window, which is the input the check has to be able
// to dissent on.
test('a partial attribution failure is reported while genuine clients keep arriving', async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-attribution-partial-'));
  const server = createServer({
    dataDir,
    trustProxy: true,
    adminToken: 'admin-tok',
    attributionWindowMs: 60_000, // one window for the whole test; no waiting
    limits: { lookupRate: { windowMs: 60_000, max: 1000 } },
    log: () => {},
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  const health = async () => (await (await fetch(`${base}/v1/admin/overview`, {
    headers: { 'x-telegraph-admin': 'admin-tok' },
  })).json()).health;
  const distinct = async (n) => {
    for (let i = 0; i < n; i += 1) {
      assert.equal((await fetch(`${base}/v1/directory`, {
        headers: { 'cf-connecting-ip': `203.0.113.${(i % 250) + 1}` },
      })).status, 200);
    }
  };
  const unattributable = async (n) => {
    for (let i = 0; i < n; i += 1) {
      assert.equal((await fetch(`${base}/v1/directory`)).status, 200);
    }
  };
  try {
    // A healthy relay with the ordinary trickle of local traffic: smoke tests,
    // the watchdog, a curl from the host. Below the minority band, and it must
    // stay quiet or the operator learns to ignore it.
    await distinct(38);
    await unattributable(2);
    const healthy = await health();
    assert.equal(healthy.clientAttribution.state, 'ok');
    assert.equal(healthy.clientIpsIndistinguishable, false,
      'a 5% trickle of local traffic is not an attribution failure');
    assert.equal(healthy.warning, undefined);
    assert.equal(healthy.clientAttribution.inWindow.unattributableFraction, 0.05);

    // Now one ingress of two stops forwarding. Genuine clients keep arriving on
    // the other one for the whole window — which is exactly what silenced the
    // existential check.
    await unattributable(10);
    const partial = await health();
    assert.equal(partial.clientAttribution.inWindow.observed, 50);
    assert.equal(partial.clientAttribution.inWindow.unattributable, 12);
    assert.equal(partial.clientAttribution.inWindow.distinct, 38);
    assert.ok(partial.clientAttribution.lastDistinctAgoMs < 60_000,
      'distinct clients are still arriving in this window — the case the old check called healthy');
    assert.equal(partial.clientAttribution.state, 'partial');
    assert.equal(partial.clientIpsIndistinguishable, true,
      'a quarter of the traffic sharing one bucket is a fault, not a rounding error');
    assert.match(partial.warning, /partial/);

    // The minority band is a claim about a population, so it needs a population.
    // One local poke among nine real reads is the boot-smoke-test false red that
    // started all of this, and it must not come back.
    const small = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-attribution-small-'));
    const tiny = createServer({
      dataDir: small, trustProxy: true, adminToken: 'admin-tok',
      limits: { lookupRate: { windowMs: 60_000, max: 1000 } }, log: () => {},
    });
    await new Promise((resolve) => tiny.listen(0, '127.0.0.1', resolve));
    const tinyBase = `http://127.0.0.1:${tiny.address().port}`;
    try {
      for (let i = 0; i < 9; i += 1) {
        await fetch(`${tinyBase}/v1/directory`, { headers: { 'cf-connecting-ip': `198.51.100.${i + 1}` } });
      }
      await fetch(`${tinyBase}/v1/directory`);
      const quiet = (await (await fetch(`${tinyBase}/v1/admin/overview`, {
        headers: { 'x-telegraph-admin': 'admin-tok' },
      })).json()).health;
      assert.equal(quiet.clientAttribution.inWindow.unattributableFraction, 0.1);
      assert.equal(quiet.clientAttribution.state, 'insufficient_sample',
        'at ten requests a tenth is one request, so the band is not evaluated — '
        + 'but unevaluated must not serialize as passed');
      assert.equal(quiet.clientIpsIndistinguishable, false);
    } finally {
      await new Promise((resolve) => tiny.close(resolve));
      fs.rmSync(small, { recursive: true, force: true });
    }

    // Total collapse still reads as total collapse, not as a partial one: the
    // majority band takes no floor, because "one loopback poke and nothing else"
    // is 100% and saying so is true.
    await distinct(0);
    await unattributable(80);
    const collapsed = await health();
    assert.equal(collapsed.clientAttribution.state, 'indistinguishable');
    assert.equal(collapsed.clientIpsIndistinguishable, true);
    assert.match(collapsed.warning, /loopback/);
  } finally {
    await new Promise((resolve) => server.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

// The sample floor used to be folded into the healthy state, which made the
// verdict non-monotone in severity: nine unattributable requests read quieter
// than two, because nine of nineteen misses the floor and two of twenty clears
// it. The floor belongs on the report, not on the band — under it the answer is
// "not evaluated", which is a third thing and must serialize as a third thing.
test('a sample floor never makes more unattributable traffic read quieter than less', async () => {
  const run = async (distinctCount, unattributableCount) => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-attribution-floor-'));
    const srv = createServer({
      dataDir: dir,
      trustProxy: true,
      adminToken: 'admin-tok',
      attributionWindowMs: 60_000,
      limits: { lookupRate: { windowMs: 60_000, max: 1000 } },
      log: () => {},
    });
    await new Promise((resolve) => srv.listen(0, '127.0.0.1', resolve));
    const base = `http://127.0.0.1:${srv.address().port}`;
    try {
      for (let i = 0; i < distinctCount; i += 1) {
        await fetch(`${base}/v1/directory`, { headers: { 'cf-connecting-ip': `203.0.113.${(i % 250) + 1}` } });
      }
      for (let i = 0; i < unattributableCount; i += 1) await fetch(`${base}/v1/directory`);
      return (await (await fetch(`${base}/v1/admin/overview`, {
        headers: { 'x-telegraph-admin': 'admin-tok' },
      })).json()).health.clientAttribution;
    } finally {
      await new Promise((resolve) => srv.close(resolve));
      fs.rmSync(dir, { recursive: true, force: true });
    }
  };

  // 9 of 19 — 47% unattributable, one request short of the floor.
  const worse = await run(10, 9);
  assert.equal(worse.inWindow.observed, 19);
  assert.equal(worse.inWindow.unattributable, 9);
  // 2 of 20 — 10% unattributable, one request past the floor.
  const better = await run(18, 2);
  assert.equal(better.inWindow.observed, 20);
  assert.equal(better.inWindow.unattributable, 2);

  assert.equal(better.state, 'partial');
  assert.notEqual(worse.state, 'ok',
    'a 47% unattributable window must not report the same state as a clean one just '
    + 'because it is one request under the sample floor');
  assert.equal(worse.state, 'insufficient_sample');
});
