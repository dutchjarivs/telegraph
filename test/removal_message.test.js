// What the relay *says* after an operator removes an agent.
//
// `unknown_sender` has always had two causes and one string. hardening.test.js
// covers the first ("well-formed, never registered") and asserts the error
// code, which made the branch look tested. The second cause — registered here,
// then removed by the operator, or lost to a restore of an older snapshot —
// produces the identical response, and the old hint ("register first") asserted
// the cause the relay cannot actually know. Worse, its remedy works: the
// address is derived from the signing key, so the caller re-registers, lands on
// the same address, and an operator-side deletion is filed as the caller's own
// setup mistake. Nothing in the access log distinguishes the two (it records
// the status code, not the error code), so the misattribution is uncountable.
//
// These tests assert the message text and the behaviour the message describes.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

const ADMIN = 'test-admin-token';
let server;
let base;
let dataDir;
let bob;

test.before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'telegraph-removal-'));
  // Raised because a re-registration after removal counts as a *new* identity
  // against the anti-sybil cap (`prev` is null once the record is gone), so a
  // handful of remove/re-register cycles from one host trips it at the default 5.
  server = createServer({ dataDir, adminToken: ADMIN, limits: { registerRate: { max: 50, windowMs: 60_000 } } });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
  bob = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await bob.register({ handle: 'bob' });
});

test.after(async () => {
  await new Promise((resolve) => server.close(resolve));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

const admin = (pathname, body) =>
  fetch(base + pathname, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-telegraph-admin': ADMIN },
    body: JSON.stringify(body),
  });

// A wire from an address the relay has no record of, signed properly, so the
// only thing that can reject it is the missing registration.
async function sendRaw(client, toBoxKey, toAddress, text) {
  const { encrypt, messageFields, signFields } = await import('../src/crypto.js');
  const { nonce, ciphertext } = encrypt(text, toBoxKey, client.identity.boxSecretKey);
  const ts = Date.now();
  const sig = signFields(
    messageFields(toAddress, client.identity.address, nonce, ciphertext, ts),
    client.identity.signSecretKey,
  );
  const res = await fetch(base + '/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ to: toAddress, from: client.identity.address, nonce, ciphertext, ts, sig }),
  });
  return { status: res.status, body: await res.json() };
}

test('a removed sender is not told they never registered', async () => {
  const carol = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await carol.register({ handle: 'carol' });
  const gone = await admin('/v1/admin/agents/remove', { address: carol.identity.address });
  assert.equal(gone.status, 200);

  const res = await sendRaw(carol, bob.identity.boxPublicKey, bob.identity.address, 'still here');
  assert.equal(res.status, 401);
  assert.equal(res.body.error, 'unknown_sender');
  // The relay cannot know which cause this is, so it must not name one.
  assert.match(res.body.hint, /or its registration was removed/);
  assert.match(res.body.hint, /cannot tell which/);
  assert.doesNotMatch(res.body.hint, /^register first/);
});

test('the remedy the hint names works, which is why naming one cause was wrong', async () => {
  const dave = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await dave.register({ handle: 'dave' });
  const address = dave.identity.address;
  await admin('/v1/admin/agents/remove', { address });

  // Same keypair, fresh signed payload: back at the same address, sending again.
  await dave.register({ handle: 'dave' });
  assert.equal(dave.identity.address, address, 'address is derived from the signing key');
  const res = await sendRaw(dave, bob.identity.boxPublicKey, bob.identity.address, 'back');
  assert.equal(res.status, 200);
});

test('removal tells the operator it is not enforcement', async () => {
  const erin = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await erin.register({ handle: 'erin' });
  const gone = await admin('/v1/admin/agents/remove', { address: erin.identity.address });
  const body = await gone.json();
  assert.match(body.note, /re-register and reclaim the same address/);
  assert.match(body.note, /suspend/);
});

test('suspension is the durable control: it survives removal and re-registration', async () => {
  const frank = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await frank.register({ handle: 'frank' });
  await admin('/v1/admin/agents/suspend', { address: frank.identity.address, suspended: true, note: 'abuse' });
  await admin('/v1/admin/agents/remove', { address: frank.identity.address });
  await frank.register({ handle: 'frank' }); // same keys, same address

  const res = await sendRaw(frank, bob.identity.boxPublicKey, bob.identity.address, 'try me');
  assert.equal(res.status, 403);
  assert.equal(res.body.error, 'sender_suspended');
});

// The ban above survives removal, which is the design. What nothing accounted
// for is that it survives into a state no view could show: `suspendedAgents`
// and every per-agent `suspended` field are joins over listAgents(), and a
// removed agent is not in that list. The send gate reads moderation by address
// directly, so the ban still fires. Enforced and unenumerable at the same time
// — and an operator cannot lift a ban they cannot find.
test('a suspension that outlives its agent record is still listed for the operator', async () => {
  const grace = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await grace.register({ handle: 'grace' });
  const address = grace.identity.address;
  await admin('/v1/admin/agents/suspend', { address, suspended: true, note: 'abuse' });
  await admin('/v1/admin/agents/remove', { address });

  const res = await fetch(base + '/v1/admin/overview', { headers: { 'x-telegraph-admin': ADMIN } });
  const body = await res.json();

  // The agent-list view genuinely has nothing to show: the record is gone.
  assert.equal(body.agents.some((a) => a.address === address), false);
  const countedAsAgent = body.agents.filter((a) => a.suspended).map((a) => a.address);
  assert.equal(countedAsAgent.includes(address), false);
  assert.equal(body.totals.reports.suspendedAgents, countedAsAgent.length);

  // The enforcement is still real, so it has to appear somewhere.
  const latent = body.latentSuspensions.find((m) => m.address === address);
  assert.equal(body.totals.reports.suspendedLatent, body.latentSuspensions.length);
  assert.ok(latent, 'a ban with no agent record must still be enumerable');
  assert.equal(latent.note, 'abuse');

  // And it is not a stale record: the ban fires the moment that key returns.
  await grace.register({ handle: 'grace' });
  const send = await sendRaw(grace, bob.identity.boxPublicKey, bob.identity.address, 'try me');
  assert.equal(send.status, 403);
  assert.equal(send.body.error, 'sender_suspended');

  // Once it is back in the agent list, it must not be counted in both places.
  const after = await (await fetch(base + '/v1/admin/overview', { headers: { 'x-telegraph-admin': ADMIN } })).json();
  assert.equal(after.agents.some((a) => a.address === address && a.suspended), true);
  assert.equal(after.latentSuspensions.some((m) => m.address === address), false);
});
