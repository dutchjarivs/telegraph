// Attachments at the relay boundary. Attachments ride E2E inside the sealed box,
// so the relay never interprets them — they only matter to the relay as *bigger
// ciphertext*. These tests pin the two relay-side facts that follow from that:
//   1. the ciphertext cap is the only gate, it's env/limits-configurable, and a
//      large attachment wire is accepted once the cap allows it and metered by
//      the same per-byte token formula as any wire (no separate attachment meter);
//   2. at the default cap an oversized wire is refused with `too_large`, and the
//      relay stores no attachment-shaped fields (it's blind to the file).
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
// 512 KB ciphertext cap → room for a real attachment; the default is 16 KB.
const BIG_CAP = 512 * 1024;

before(async () => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-attach-'));
  server = createServer({
    dataDir,
    limits: {
      registerRate: { windowMs: 60 * 60_000, max: 10_000 },
      ciphertextB64: BIG_CAP,
      // A big attachment is a genuinely expensive wire under the standard meter;
      // fund the free allowance so the test exercises delivery, not billing.
      freeDailyTokens: 10_000_000,
    },
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((r) => server.close(r));
  fs.rmSync(dataDir, { recursive: true, force: true });
});

let n = 0;
const uniq = (p) => `${p}-${Date.now().toString(36)}-${n++}`;

async function agent(handle) {
  const c = new TelegraphClient({ server: base, identity: TelegraphClient.generateIdentity() });
  await c.register({ handle }); // attachments:true by default → advertises the cap
  return c;
}

test('a large attachment wire is accepted when the cap allows it and round-trips', async () => {
  const alice = await agent(uniq('att-a'));
  const bob = await agent(uniq('att-b'));

  // ~100 KB of non-trivial bytes (a gradient, not all-zero, so a bug that dropped
  // or truncated the payload would change the decoded contents).
  const payload = new Uint8Array(100 * 1024);
  for (let i = 0; i < payload.length; i++) payload[i] = i % 251;

  const sent = await alice.send(bob.identity.address, 'photo attached', {
    attachments: [{ name: 'pic.bin', mime: 'application/octet-stream', data: payload }],
  });
  assert.equal(sent.attachments, 1);
  // Metered by the standard per-byte formula: a 100 KB attachment is a very
  // expensive wire (thousands of tokens), never a flat/free attachment charge.
  assert.ok(sent.tokens > 10_000, `expected a large token charge, got ${sent.tokens}`);

  const [wire] = await bob.inbox({ ack: true });
  assert.equal(wire.text, 'photo attached');
  assert.equal(wire.verified, true);
  assert.equal(wire.attachments.length, 1);
  assert.equal(wire.attachments[0].size, payload.length);
  assert.deepEqual([...wire.attachments[0].data], [...payload]);
});

test('the relay stores only ciphertext for an attachment wire (no plaintext file fields)', async () => {
  const alice = await agent(uniq('att-c'));
  const bob = await agent(uniq('att-d'));
  const marker = new TextEncoder().encode('RELAY-MUST-NOT-SEE-THIS-BLOB');
  await alice.send(bob.identity.address, 'x', {
    attachments: [{ name: 'secret.txt', mime: 'text/plain', data: marker }],
  });
  // Read the stored mailbox straight off disk — the relay's own view.
  const raw = fs.readFileSync(path.join(dataDir, 'mailboxes', `${bob.identity.address}.json`), 'utf8');
  assert.ok(!raw.includes('RELAY-MUST-NOT-SEE-THIS-BLOB'));
  assert.ok(!raw.includes('secret.txt'));
  const stored = JSON.parse(raw)[0];
  assert.equal(stored.attachments, undefined);
  assert.equal(stored.name, undefined);
});

test('a wire over the ciphertext cap is refused with too_large', async () => {
  const alice = await agent(uniq('att-e'));
  const bob = await agent(uniq('att-f'));
  // Bytes chosen so the sealed+base64 ciphertext exceeds the 512 KB cap.
  const tooBig = new Uint8Array(600 * 1024);
  await assert.rejects(
    alice.send(bob.identity.address, 'oversize', { attachments: [{ name: 'huge.bin', data: tooBig }] }),
    (e) => /too_large/.test(String(e.message)),
  );
});
