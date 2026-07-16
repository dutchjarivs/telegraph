// Webhooks / push delivery: registration (signed), notify-only delivery with an
// HMAC signature, SSRF refusal at delivery time, and the retry/circuit-breaker.
// Delivery is exercised with an injected transport + DNS lookup so no real
// socket opens; the SSRF range check still runs against the (injected) resolved
// IP, which is the property that matters.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';
import { signPayload, verifyWebhookSignature } from '../src/webhook.js';

const REG_RATE = { registerRate: { windowMs: 60 * 60_000, max: 10_000 } };

// A lookup stub that resolves any hostname to a fixed IP list.
const lookupTo = (ip, family = 4) => (host, opts, cb) => cb(null, [{ address: ip, family }]);

async function withServer(webhook, fn) {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-wh-'));
  const server = createServer({ dataDir, limits: REG_RATE, webhook });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  let n = 0;
  const agent = async (p) => {
    const c = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
    await c.register({ handle: `${p}-${n++}` });
    return c;
  };
  try {
    await fn({ server, base, agent });
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
}

test('register / read / remove a webhook (secret shown once, never echoed)', async () => {
  await withServer({}, async ({ agent }) => {
    const bob = await agent('wh-bob');
    const reg = await bob.setWebhook('https://hooks.example.com/telegraph');
    assert.equal(reg.ok, true);
    assert.equal(reg.url, 'https://hooks.example.com/telegraph');
    assert.ok(reg.secret && reg.secret.length >= 32, 'a secret is generated and returned once');

    const got = await bob.getWebhook();
    assert.equal(got.url, 'https://hooks.example.com/telegraph');
    assert.equal(got.disabled, false);
    assert.equal(got.secret, undefined, 'GET never echoes the secret');

    const removed = await bob.removeWebhook();
    assert.equal(removed.removed, true);
    await assert.rejects(bob.getWebhook(), (e) => e.status === 404);
  });
});

test('registration refuses a non-https URL and a blocked IP literal', async () => {
  await withServer({}, async ({ agent }) => {
    const bob = await agent('wh-bad');
    await assert.rejects(bob.setWebhook('http://hooks.example.com'), (e) => e.data?.error === 'bad_webhook_url');
    await assert.rejects(bob.setWebhook('https://127.0.0.1/hook'), (e) => e.data?.error === 'bad_webhook_url');
  });
});

test('verifyWebhookSignature accepts a genuine signature and rejects tampering', () => {
  const secret = 'a'.repeat(40);
  const body = JSON.stringify({ event: 'wire.received', id: 'x' });
  const sig = signPayload(body, secret);
  assert.equal(verifyWebhookSignature(body, secret, sig), true);
  assert.equal(verifyWebhookSignature(body + ' ', secret, sig), false, 'body tamper fails');
  assert.equal(verifyWebhookSignature(body, 'wrong-secret', sig), false, 'wrong secret fails');
  assert.equal(verifyWebhookSignature(body, secret, 'sha256=deadbeef'), false, 'forged sig fails');
  assert.equal(verifyWebhookSignature(body, secret, undefined), false, 'missing header fails cleanly');
});

test('a delivered wire fires a notify-only, HMAC-signed webhook', async () => {
  const calls = [];
  const transport = async ({ href, headers, body }) => { calls.push({ href, headers, body }); return { status: 200 }; };
  await withServer({ transport, lookup: lookupTo('93.184.216.34'), allowPrivate: false }, async ({ server, agent }) => {
    const alice = await agent('wh-a');
    const bob = await agent('wh-b');
    const reg = await bob.setWebhook('https://hooks.example.com/tg');

    const sent = await alice.send(bob.identity.address, 'ping');
    await server._webhooksIdle();

    assert.equal(calls.length, 1, 'exactly one delivery');
    const { headers, body } = calls[0];
    const payload = JSON.parse(body);
    // Notify-only: metadata the recipient already has, and NO ciphertext.
    assert.deepEqual(Object.keys(payload).sort(), ['event', 'from', 'id', 'to', 'ts']);
    assert.equal(payload.event, 'wire.received');
    assert.equal(payload.to, bob.identity.address);
    assert.equal(payload.from, alice.identity.address);
    assert.equal(payload.id, sent.id);
    assert.equal(payload.ciphertext, undefined);
    // Signature verifies against the secret the relay handed back at registration.
    assert.equal(headers['x-telegraph-signature'], signPayload(body, reg.secret));
    assert.ok(headers['x-telegraph-delivery'], 'carries a delivery id');
  });
});

test('delivery refuses a host that resolves to a blocked IP (DNS rebinding guard)', async () => {
  let called = false;
  const transport = async () => { called = true; return { status: 200 }; };
  // Host passes the registration parse (it is a name, not a literal) but resolves
  // to loopback — delivery must refuse it and never hit the transport.
  await withServer({ transport, lookup: lookupTo('127.0.0.1'), allowPrivate: false, maxAttempts: 3, backoffMs: [1, 1, 1] },
    async ({ server, agent }) => {
      const alice = await agent('wh-ssrf-a');
      const bob = await agent('wh-ssrf-b');
      await bob.setWebhook('https://rebind.example.com/hook');
      await alice.send(bob.identity.address, 'ping');
      await server._webhooksIdle();

      assert.equal(called, false, 'transport is never reached for a blocked resolution');
      const hook = await bob.getWebhook();
      assert.equal(hook.disabled, true, 'a blocked target is a permanent failure → disabled');
      assert.match(hook.lastError ?? '', /blocked_ip/);
    });
});

test('the retry breaker disables a webhook after repeated transient failures', async () => {
  let attempts = 0;
  const transport = async () => { attempts += 1; throw Object.assign(new Error('boom'), { reason: 'timeout' }); };
  await withServer({ transport, lookup: lookupTo('93.184.216.34'), allowPrivate: false, maxAttempts: 2, backoffMs: [1, 1], breakerThreshold: 2 },
    async ({ server, agent }) => {
      const alice = await agent('wh-brk-a');
      const bob = await agent('wh-brk-b');
      await bob.setWebhook('https://flaky.example.com/hook');

      // First delivery: 2 attempts, both fail → failure #1.
      await alice.send(bob.identity.address, 'one');
      await server._webhooksIdle();
      let hook = await bob.getWebhook();
      assert.equal(hook.disabled, false);
      assert.equal(hook.failures, 1);

      // Second delivery: failure #2 → hits the breaker threshold → disabled.
      await alice.send(bob.identity.address, 'two');
      await server._webhooksIdle();
      hook = await bob.getWebhook();
      assert.equal(hook.disabled, true);
      assert.ok(hook.failures >= 2);

      // Disabled → no further attempts even on new wires.
      const before = attempts;
      await alice.send(bob.identity.address, 'three');
      await server._webhooksIdle();
      assert.equal(attempts, before, 'a disabled webhook is not retried');
    });
});

test('a duplicate wire does not fire a second webhook', async () => {
  const calls = [];
  const transport = async ({ body }) => { calls.push(body); return { status: 200 }; };
  await withServer({ transport, lookup: lookupTo('93.184.216.34') }, async ({ server, agent, base }) => {
    const alice = await agent('wh-dup-a');
    const bob = await agent('wh-dup-b');
    await bob.setWebhook('https://hooks.example.com/tg');

    // Send, then replay the exact same signed envelope by hand.
    const { encrypt } = await import('../src/crypto.js');
    const rec = await alice.lookup(bob.identity.address);
    const { signFields, messageFields } = await import('../src/crypto.js');
    const { nonce, ciphertext } = encrypt('dup', rec.boxPublicKey, alice.identity.boxSecretKey);
    const ts = Date.now();
    const sig = signFields(messageFields(rec.address, alice.identity.address, nonce, ciphertext, ts), alice.identity.signSecretKey);
    const envelope = { to: rec.address, from: alice.identity.address, nonce, ciphertext, ts, sig };
    const post = () => fetch(base + '/v1/messages', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(envelope) });
    await post();
    await post(); // duplicate
    await server._webhooksIdle();
    assert.equal(calls.length, 1, 'only the first, real delivery notifies');
  });
});
