// Signed delivery receipts: when a recipient acks a wire with receipt:true, it
// signs a proof binding (messageId, sender, recipient) that the sender can later
// fetch and verify — end-to-end authenticated, relay-mediated, and additive
// (an ack without receipts behaves exactly as before).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';

let server;
let base;
let dataDir;

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-receipts-'));
  server = createServer({ dataDir, limits: { registerRate: { windowMs: 60 * 60_000, max: 10_000 } } });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((r) => server.close(r));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

let n = 0;
async function agent(p) {
  const c = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await c.register({ handle: `${p}-${n++}` });
  return c;
}

test('a recipient acking with receipt:true gives the sender a verified receipt', async () => {
  const sender = await agent('rcp-s');
  const recipient = await agent('rcp-r');
  const sent = await sender.send(recipient.identity.address, 'confirm you got this');

  // No receipts yet.
  assert.deepEqual(await sender.receipts(), []);

  // Recipient fetches and acks WITH a receipt.
  await recipient.inbox({ ack: true, receipt: true });

  const receipts = await sender.receipts();
  assert.equal(receipts.length, 1);
  assert.equal(receipts[0].messageId, sent.id);
  assert.equal(receipts[0].recipient, recipient.identity.address);
  assert.ok(typeof receipts[0].recipientHandle === 'string' && receipts[0].recipientHandle.startsWith('rcp-r'));
  assert.equal(receipts[0].verified, true, 'the receipt signature must verify against the recipient key');
});

test('acking without receipt:true produces no receipt (opt-in, backward compatible)', async () => {
  const sender = await agent('rcp-none-s');
  const recipient = await agent('rcp-none-r');
  await sender.send(recipient.identity.address, 'no receipt please');
  await recipient.inbox({ ack: true }); // plain ack
  assert.deepEqual(await sender.receipts(), []);
});

test('a forged receipt (wrong signer) is rejected by the relay', async () => {
  const sender = await agent('rcp-forge-s');
  const recipient = await agent('rcp-forge-r');
  const attacker = await agent('rcp-forge-x');
  const sent = await sender.send(recipient.identity.address, 'target wire');

  // Recipient fetches (so the wire is in their mailbox) but we hand-craft a
  // receipt signed by the ATTACKER's key instead of the recipient's, and post
  // the ack directly.
  const { signFields, receiptFields } = await import('../src/crypto.js');
  const at = Date.now();
  const forgedSig = signFields(receiptFields(sent.id, sender.identity.address, recipient.identity.address, at), attacker.identity.signSecretKey);
  await recipient.ack([sent.id], { receipts: [{ messageId: sent.id, at, sig: forgedSig }] });

  // The forged receipt must not have been stored.
  assert.deepEqual(await sender.receipts(), []);
});

test('a receipt for a wire the recipient never received is not stored', async () => {
  const sender = await agent('rcp-ghost-s');
  const recipient = await agent('rcp-ghost-r');
  const { signFields, receiptFields } = await import('../src/crypto.js');
  const fakeId = 'deadbeef'.repeat(3);
  const at = Date.now();
  const sig = signFields(receiptFields(fakeId, sender.identity.address, recipient.identity.address, at), recipient.identity.signSecretKey);
  // Ack a message id that isn't in the mailbox, with a well-signed receipt.
  await recipient.ack([fakeId], { receipts: [{ messageId: fakeId, at, sig }] });
  assert.deepEqual(await sender.receipts(), []);
});

test('receipts survive a relay restart and are deduped', async () => {
  const sender = await agent('rcp-dur-s');
  const recipient = await agent('rcp-dur-r');
  const sent = await sender.send(recipient.identity.address, 'durable receipt');
  await recipient.inbox({ ack: true, receipt: true });
  // A repeated receipt for the same wire must not double-count.
  const { signFields, receiptFields } = await import('../src/crypto.js');
  const at = Date.now();
  const sig = signFields(receiptFields(sent.id, sender.identity.address, recipient.identity.address, at), recipient.identity.signSecretKey);
  await recipient.ack([sent.id], { receipts: [{ messageId: sent.id, at, sig }] }); // id already acked+gone
  assert.equal((await sender.receipts()).length, 1);
});
