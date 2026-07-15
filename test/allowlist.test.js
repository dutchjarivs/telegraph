// Recipient allowlists: the opt-in inverse of the block list. Dormant by
// default (everyone accepted); once mode is on, only listed senders get through,
// and the refusal is explicit and uncharged — same contract as a block.
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
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tg-allow-'));
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

test('with mode off, the allowlist is dormant and everyone can wire', async () => {
  const owner = await agent('al-owner');
  const stranger = await agent('al-stranger');
  await owner.allow(stranger.identity.address); // on the list, but mode is off
  const r = await stranger.send(owner.identity.address, 'hi while dormant');
  assert.equal(r.duplicate, false);
  assert.equal((await owner.inbox({ ack: true })).length, 1);
});

test('with mode on, only allowlisted senders get through; others are refused and not charged', async () => {
  const owner = await agent('al2-owner');
  const friend = await agent('al2-friend');
  const stranger = await agent('al2-stranger');
  await owner.allow(friend.identity.address);
  await owner.allowlistMode(true);

  // friend is allowlisted → delivered
  await friend.send(owner.identity.address, 'let me in');
  // stranger is not → explicit refusal
  const beforeUsed = (await stranger.credits()).freeUsedToday;
  await assert.rejects(
    stranger.send(owner.identity.address, 'unsolicited'),
    (e) => e.status === 403 && e.data?.error === 'recipient_not_accepting',
  );
  const afterUsed = (await stranger.credits()).freeUsedToday;
  assert.equal(afterUsed, beforeUsed, 'a refused sender is not charged');

  const wires = await owner.inbox({ ack: true });
  assert.equal(wires.length, 1);
  assert.equal(wires[0].text, 'let me in');
});

test('removing a sender from the list stops their wires once mode is on', async () => {
  const owner = await agent('al3-owner');
  const s = await agent('al3-sender');
  await owner.allow(s.identity.address);
  await owner.allowlistMode(true);
  await s.send(owner.identity.address, 'first, allowed');
  await owner.disallow(s.identity.address);
  await assert.rejects(
    s.send(owner.identity.address, 'second, now blocked'),
    (e) => e.data?.error === 'recipient_not_accepting',
  );
  assert.equal((await owner.inbox({ ack: true })).length, 1);
});

test('enabling mode with an empty list warns and accepts from no one', async () => {
  const owner = await agent('al4-owner');
  const s = await agent('al4-sender');
  const r = await owner.allowlistMode(true);
  assert.match(r.warning ?? '', /empty/);
  await assert.rejects(
    s.send(owner.identity.address, 'anyone home?'),
    (e) => e.data?.error === 'recipient_not_accepting',
  );
});

test('a recipient can always wire itself even under strict mode', async () => {
  const owner = await agent('al5-owner');
  await owner.allowlistMode(true);
  const r = await owner.send(owner.identity.address, 'note to self');
  assert.equal(r.duplicate, false);
  assert.equal((await owner.inbox({ ack: true }))[0].text, 'note to self');
});

test('GET allowlist reports mode and entries; cannot allowlist self', async () => {
  const owner = await agent('al6-owner');
  const f = await agent('al6-friend');
  await owner.allow(f.identity.address, { note: 'trusted' });
  const list = await owner.allowlist();
  assert.equal(list.mode, false);
  assert.equal(list.count, 1);
  assert.equal(list.entries[0].note, 'trusted');
  await assert.rejects(
    owner.allow(owner.identity.address),
    (e) => e.data?.error === 'cannot_allowlist_self',
  );
});
