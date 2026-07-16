// Backup and restore.
//
// A backup tool is only worth the confidence you can place in it, and confidence
// comes from exactly two properties: a backup that verifies really does contain
// what was on disk, and a restore really does put the relay back the way it was.
// Everything below is one of those two, plus the ways each can go wrong — a
// damaged file, a torn read, a malicious path, a live relay underneath you.
//
// The strongest test here is the round trip: build a relay with real state
// (agents, balances, queued mail, blocks), snapshot it, destroy the data
// directory, restore, restart, and check that a *wire sent before the backup is
// still readable after the restore*. That's the property an operator actually
// cares about, and it's the one that no amount of checksum-matching implies.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { createHash } from 'node:crypto';
import { createServer } from '../src/server.js';
import { TelegraphClient } from '../src/client.js';
import {
  createSnapshot, serialize, parse, verify, restore, relayIsLive,
  BACKUP_FORMAT, BACKUP_VERSION, EXCLUDED_SECRETS,
} from '../src/backup.js';

const tmp = (tag) => fs.mkdtempSync(path.join(os.tmpdir(), `telegraph-backup-${tag}-`));

// Stand up a relay, give it real state, and hand back everything needed to
// inspect it. Used by the round-trip tests below.
async function liveRelay(dataDir) {
  const server = createServer({ dataDir });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return {
    server,
    base,
    client: (identity) => new TelegraphClient({ server: base, identity }),
    close: () => new Promise((r) => server.close(r)),
  };
}

test('a snapshot captures the relay-owned files and checksums every one', async () => {
  const dataDir = tmp('capture');
  const relay = await liveRelay(dataDir);
  try {
    const alice = relay.client(TelegraphClient.generateIdentity());
    const bob = relay.client(TelegraphClient.generateIdentity());
    await alice.register({ handle: 'snap-alice' });
    await bob.register({ handle: 'snap-bob' });
    await alice.send('@snap-bob', 'in the mailbox at snapshot time');

    const { snapshot, warnings } = createSnapshot(dataDir);

    assert.equal(snapshot.format, BACKUP_FORMAT);
    assert.equal(snapshot.version, BACKUP_VERSION);
    assert.ok(Object.hasOwn(snapshot.files, 'agents.json'), 'the directory is in the backup');
    assert.ok(
      Object.keys(snapshot.files).some((f) => f.startsWith('mailboxes/') && !f.endsWith('.seen.json')),
      'the undelivered wire is in the backup',
    );
    // The replay guard has to travel with the mailbox, or a restore reopens the
    // window where an old envelope re-delivers and its sender is re-charged.
    assert.ok(
      Object.keys(snapshot.files).some((f) => f.endsWith('.seen.json')),
      'the seen/replay-guard file is in the backup',
    );
    assert.equal(snapshot.summary.agents, 2);
    assert.equal(snapshot.summary.queuedWires, 1);

    // Every file carries a checksum, and every checksum is right.
    for (const rel of Object.keys(snapshot.files)) {
      assert.ok(snapshot.sha256[rel], `${rel} has a checksum`);
    }
    assert.deepEqual(verify(snapshot), { ok: true, problems: [] });
    assert.deepEqual(warnings, [], 'an idle relay yields a clean, untorn snapshot');
  } finally {
    await relay.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('secrets are never in a backup, even when they sit in the data directory', async () => {
  const dataDir = tmp('secrets');
  const relay = await liveRelay(dataDir);
  try {
    await relay.client(TelegraphClient.generateIdentity()).register({ handle: 'secret-holder' });
    // Belt and braces: these live in the app root, not here — but if an operator
    // ever drops one in the data dir, the backup must still refuse to carry it.
    for (const name of EXCLUDED_SECRETS) fs.writeFileSync(path.join(dataDir, name), 'SUPER-SECRET-VALUE');
    fs.writeFileSync(path.join(dataDir, 'operator-notes.txt'), 'scratch');

    const { snapshot } = createSnapshot(dataDir);
    const blob = JSON.stringify(snapshot);

    assert.ok(!blob.includes('SUPER-SECRET-VALUE'), 'no secret value reached the backup');
    for (const name of EXCLUDED_SECRETS) {
      assert.ok(!Object.hasOwn(snapshot.files, name), `${name} is not a file in the backup`);
    }
    assert.ok(!Object.hasOwn(snapshot.files, 'operator-notes.txt'), 'unowned files are ignored, not swept up');
  } finally {
    await relay.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('an in-flight atomicWrite .tmp file is never mistaken for data', async () => {
  const dataDir = tmp('tmpfile');
  const relay = await liveRelay(dataDir);
  try {
    await relay.client(TelegraphClient.generateIdentity()).register({ handle: 'tmp-agent' });
    // storage.js writes tmp-then-rename; a crash mid-write leaves this behind.
    // A directory sweep would snapshot the half-written file next to its own
    // complete original. The allowlist is what stops that.
    fs.writeFileSync(path.join(dataDir, 'agents.json.tmp'), '{"half-writ');
    fs.writeFileSync(path.join(dataDir, 'mailboxes', 'TG-AAAA-BBBB-CCCC-DDDD.json.tmp'), '[{"half');

    const { snapshot, warnings } = createSnapshot(dataDir);

    assert.ok(!Object.keys(snapshot.files).some((f) => f.endsWith('.tmp')), 'no .tmp file entered the backup');
    assert.deepEqual(verify(snapshot), { ok: true, problems: [] });
    assert.deepEqual(warnings, [], 'and it is not reported as corruption — it is just not data');
  } finally {
    await relay.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('round trip: a wire sent before the backup is still readable after a restore', async () => {
  const dataDir = tmp('roundtrip');
  const aliceId = TelegraphClient.generateIdentity();
  const bobId = TelegraphClient.generateIdentity();
  let backup;

  // --- Day 1: a relay with real state, then a backup.
  const day1 = await liveRelay(dataDir);
  try {
    const alice = day1.client(aliceId);
    const bob = day1.client(bobId);
    await alice.register({ handle: 'rt-alice' });
    await bob.register({ handle: 'rt-bob' });
    await alice.send('@rt-bob', 'the message that has to survive');
    await bob.block('@rt-alice'); // some block state too
    backup = serialize(createSnapshot(dataDir).snapshot);
  } finally {
    await day1.close();
  }

  // --- The disaster: the data directory is gone.
  fs.rmSync(dataDir, { recursive: true, force: true });
  assert.ok(!fs.existsSync(dataDir), 'data really is gone');

  // --- Recovery: restore, restart, and read the mail.
  fs.mkdirSync(dataDir, { recursive: true });
  const done = restore(parse(backup), dataDir);
  assert.ok(done.written.length >= 3, 'files were written back');

  const day2 = await liveRelay(dataDir);
  try {
    const bob = day2.client(bobId);

    // The directory came back.
    const dir = await bob.directory();
    assert.deepEqual(dir.agents.map((a) => a.handle).sort(), ['rt-alice', 'rt-bob']);
    assert.ok(dir.agents.every((a) => a.verified), 'restored agent records still verify against their own keys');

    // And the actual point of the whole exercise: Bob's undelivered wire is
    // still there, still decrypts with his key, and still verifies as Alice's.
    const inbox = await bob.inbox();
    assert.equal(inbox.length, 1);
    assert.equal(inbox[0].text, 'the message that has to survive');
    assert.equal(inbox[0].verified, true, 'the restored wire still verifies against the sender key');

    // Block state survived too.
    const blocks = await bob.blocks();
    assert.equal(blocks.length, 1);
  } finally {
    await day2.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('restore is a replacement, not a merge: state created after the backup is removed', async () => {
  const dataDir = tmp('replace');
  const aliceId = TelegraphClient.generateIdentity();
  const bobId = TelegraphClient.generateIdentity();
  const relay = await liveRelay(dataDir);
  let backup;
  try {
    const alice = relay.client(aliceId);
    const bob = relay.client(bobId);
    await alice.register({ handle: 'mg-alice' });
    await bob.register({ handle: 'mg-bob' });
    backup = serialize(createSnapshot(dataDir).snapshot);
  } finally {
    await relay.close();
  }

  // After the backup, a third agent registers and is sent mail.
  const relay2 = await liveRelay(dataDir);
  let carolAddress;
  try {
    const carol = relay2.client(TelegraphClient.generateIdentity());
    await carol.register({ handle: 'mg-carol' });
    carolAddress = (await carol.lookup('@mg-carol')).address;
    await relay2.client(aliceId).send('@mg-carol', 'sent after the backup was taken');
  } finally {
    await relay2.close();
  }

  // Restoring to the earlier point must roll Carol back out of existence.
  // A restore that left her mailbox behind would leave the relay in a state
  // that never existed: a mailbox with no agent, holding wires whose sender was
  // charged in a billing file that no longer records it.
  const done = restore(parse(backup), dataDir);
  assert.ok(done.removed.some((f) => f.includes(carolAddress)), 'Carol\'s mailbox was removed, not kept');

  const relay3 = await liveRelay(dataDir);
  try {
    const dir = await relay3.client(aliceId).directory();
    assert.deepEqual(dir.agents.map((a) => a.handle).sort(), ['mg-alice', 'mg-bob'], 'Carol is gone');
    assert.ok(
      !fs.readdirSync(path.join(dataDir, 'mailboxes')).some((f) => f.includes(carolAddress)),
      'and so is her mailbox file',
    );
  } finally {
    await relay3.close();
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a damaged backup is refused, not restored', () => {
  const dataDir = tmp('damaged');
  try {
    fs.writeFileSync(path.join(dataDir, 'agents.json'), '{"TG-REAL":{"handle":"real"}}');
    const { snapshot } = createSnapshot(dataDir);

    // Bit-rot, a truncated download, a bad disk: contents no longer match the
    // checksum taken when the backup was made.
    const tampered = structuredClone(snapshot);
    tampered.files['agents.json'] = '{"TG-EVIL":{"handle":"attacker"}}';

    const check = verify(tampered);
    assert.equal(check.ok, false);
    assert.match(check.problems[0], /checksum mismatch/);

    assert.throws(() => restore(tampered, dataDir), /refusing to restore/);
    // And the data directory is untouched by the attempt.
    assert.match(fs.readFileSync(path.join(dataDir, 'agents.json'), 'utf8'), /TG-REAL/);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('a backup cannot write outside the data directory', () => {
  const dataDir = tmp('escape');
  try {
    // A backup file is an input like any other — it can arrive by scp from a box
    // you don't control. "Restore" that writes ../../.ssh/authorized_keys is how
    // a disaster-recovery tool becomes the disaster.
    for (const evil of ['../escaped.json', 'mailboxes/../../escaped.json', '/etc/passwd', 'mailboxes/sub/dir.json']) {
      const snapshot = {
        format: BACKUP_FORMAT,
        version: BACKUP_VERSION,
        createdAt: new Date().toISOString(),
        files: { [evil]: '{}' },
        sha256: {},
      };
      // Recompute a *valid* checksum, so verification passes and the path guard
      // is the only thing standing between this file and the filesystem.
      snapshot.sha256[evil] = sha256(snapshot.files[evil]);
      assert.throws(() => restore(snapshot, dataDir), /escapes the data directory|does not own/, `blocked: ${evil}`);
    }
    assert.ok(!fs.existsSync(path.join(path.dirname(dataDir), 'escaped.json')), 'nothing escaped');
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('garbage in: a non-gzip, a non-JSON, and a future-version backup all fail clearly', () => {
  assert.throws(() => parse(Buffer.from('this is not gzipped')), /not a gzip file/);

  assert.throws(() => parse(zlib.gzipSync('not json at all')), /not JSON|damaged/);
  assert.throws(() => parse(zlib.gzipSync(JSON.stringify({ format: 'borg-backup' }))), /not a Telegraph backup/);

  // A future Telegraph writes a format this build doesn't know. Guessing at it
  // is how you restore 90% of a data set and call it a success.
  assert.throws(
    () => parse(zlib.gzipSync(JSON.stringify({ format: BACKUP_FORMAT, version: BACKUP_VERSION + 1, files: {} }))),
    /upgrade Telegraph before restoring/,
  );
});

test('relayIsLive is what stops a restore under a running relay', async () => {
  const dataDir = tmp('live');
  const relay = await liveRelay(dataDir);
  const port = Number(new URL(relay.base).port);
  try {
    // This check is not politeness. storage.js holds the whole data set in
    // memory and rewrites each file wholesale, so a restore under a live relay
    // is silently reverted by its next write — leaving the operator believing
    // data is back when it is already gone again.
    assert.equal(await relayIsLive(port), true, 'a serving relay is detected');
  } finally {
    await relay.close();
  }
  assert.equal(await relayIsLive(port), false, 'a stopped relay is not');
  // A closed port must not hang the check.
  assert.equal(await relayIsLive(1), false);
  fs.rmSync(dataDir, { recursive: true, force: true });
});

test('an empty data directory backs up and restores as an empty relay', () => {
  const dataDir = tmp('empty');
  try {
    const { snapshot, warnings } = createSnapshot(dataDir);
    assert.deepEqual(snapshot.files, {});
    assert.deepEqual(warnings, []);
    assert.equal(verify(snapshot).ok, true);
    const done = restore(snapshot, dataDir);
    assert.deepEqual(done.written, []);
    assert.deepEqual(done.removed, []);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

test('the backup survives a real gzip round trip through the filesystem', () => {
  const dataDir = tmp('gzip');
  const outDir = tmp('gzip-out');
  try {
    fs.writeFileSync(path.join(dataDir, 'agents.json'), JSON.stringify({ 'TG-A': { handle: 'a' } }, null, 2));
    fs.writeFileSync(path.join(dataDir, 'billing.json'), JSON.stringify({ 'TG-A': { credits: 4200 } }, null, 2));

    const file = path.join(outDir, 'b.json.gz');
    fs.writeFileSync(file, serialize(createSnapshot(dataDir).snapshot));

    const reloaded = parse(fs.readFileSync(file));
    assert.equal(verify(reloaded).ok, true);
    // The number that matters: credits are money someone paid for.
    assert.equal(JSON.parse(reloaded.files['billing.json'])['TG-A'].credits, 4200);
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
    fs.rmSync(outDir, { recursive: true, force: true });
  }
});

test('the backup captures the newer data files and never carries webhook secrets', () => {
  const dataDir = tmp('coverage');
  try {
    // A relay that has exercised every feature that writes to disk. The backup
    // sees on-disk state; how it got there doesn't matter, so write it directly.
    fs.writeFileSync(path.join(dataDir, 'agents.json'), '{"TG-A":{"handle":"a"}}');
    fs.writeFileSync(path.join(dataDir, 'allowlist.json'), '{"TG-A":{"mode":true,"entries":{"TG-B":{"at":1,"note":""}}}}');
    fs.writeFileSync(path.join(dataDir, 'quotas.json'), '{"TG-A":{"perSenderDailyMax":5}}');
    fs.writeFileSync(path.join(dataDir, 'quota-counts.json'), '{"2026-07-15":{"TG-B":{"TG-A":2}}}');
    fs.writeFileSync(path.join(dataDir, 'audit.json'), '[{"at":1,"action":"credits.grant","actor":"admin"}]');
    fs.mkdirSync(path.join(dataDir, 'idempotency'), { recursive: true });
    fs.writeFileSync(path.join(dataDir, 'idempotency', 'TG-B.json'), '{"k:abc":{"id":"x","at":1}}');
    fs.mkdirSync(path.join(dataDir, 'receipts'), { recursive: true });
    fs.writeFileSync(path.join(dataDir, 'receipts', 'TG-B.json'), '[{"messageId":"x","recipient":"TG-A"}]');
    // A webhook registration carries a per-hook HMAC secret — must NOT be backed up.
    fs.writeFileSync(path.join(dataDir, 'webhooks.json'), '{"TG-A":{"url":"https://x/h","secret":"WEBHOOK-SECRET-XYZ"}}');

    const { snapshot } = createSnapshot(dataDir);
    for (const f of ['allowlist.json', 'quotas.json', 'quota-counts.json', 'audit.json', 'idempotency/TG-B.json', 'receipts/TG-B.json']) {
      assert.ok(Object.hasOwn(snapshot.files, f), `${f} is now captured (was silently dropped before)`);
    }
    assert.ok(!Object.hasOwn(snapshot.files, 'webhooks.json'), 'webhooks.json is excluded');
    assert.ok(!JSON.stringify(snapshot).includes('WEBHOOK-SECRET-XYZ'), 'no webhook secret leaked into the backup');
    assert.deepEqual(snapshot.excludedData, ['webhooks.json']);
    assert.equal(verify(snapshot).ok, true);

    // Round-trip into a fresh dir: every captured file returns byte-identical,
    // and the excluded webhook file is not resurrected.
    const out = tmp('coverage-out');
    try {
      restore(parse(serialize(snapshot)), out);
      for (const f of ['allowlist.json', 'quotas.json', 'audit.json', 'idempotency/TG-B.json', 'receipts/TG-B.json']) {
        assert.equal(fs.readFileSync(path.join(out, f), 'utf8'), fs.readFileSync(path.join(dataDir, f), 'utf8'), `${f} round-trips intact`);
      }
      assert.ok(!fs.existsSync(path.join(out, 'webhooks.json')), 'webhooks.json is not restored');
    } finally {
      fs.rmSync(out, { recursive: true, force: true });
    }
  } finally {
    fs.rmSync(dataDir, { recursive: true, force: true });
  }
});

// --- small helpers ----------------------------------------------------------
const sha256 = (text) => createHash('sha256').update(Buffer.from(text, 'utf8')).digest('hex');
