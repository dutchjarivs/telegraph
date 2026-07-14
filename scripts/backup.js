#!/usr/bin/env node
// Backup / verify / restore the relay's data directory.
//
//   npm run backup                    take a snapshot (safe while the relay runs)
//   node scripts/backup.js list       what you've got, newest first
//   node scripts/backup.js verify <f> prove a backup is intact (do this on a schedule)
//   node scripts/backup.js restore <f>  put it back (relay must be stopped)
//
// Exit 0 = fine, 1 = something's wrong. Cron-friendly.
import fs from 'node:fs';
import path from 'node:path';
import readline from 'node:readline';
import {
  createSnapshot, serialize, parse, verify, restore, relayIsLive, RESTORE_NOTES,
} from '../src/backup.js';

const env = { ...readDotEnv(path.resolve('.env')), ...process.env };
const [cmd = 'create', ...rest] = process.argv.slice(2);
const flags = new Set(rest.filter((a) => a.startsWith('--')));
const args = rest.filter((a) => !a.startsWith('--'));
const opt = (name, fallback) => {
  const hit = rest.find((a) => a.startsWith(`--${name}=`));
  return hit ? hit.slice(name.length + 3) : fallback;
};

const dataDir = path.resolve(opt('data', env.TELEGRAPH_DATA_DIR ?? './data'));
const backupDir = path.resolve(opt('out', env.TELEGRAPH_BACKUP_DIR ?? './backups'));
const port = Number(opt('port', env.TELEGRAPH_PORT ?? 7787));

try {
  await main();
} catch (err) {
  console.error(`\n  ✗ ${err.message}\n`);
  process.exitCode = 1;
}

async function main() {
  switch (cmd) {
    case 'create': return create();
    case 'list': return list();
    case 'verify': return doVerify();
    case 'restore': return doRestore();
    default:
      throw new Error(`unknown command "${cmd}" — expected create, list, verify, or restore`);
  }
}

// --- create -----------------------------------------------------------------
async function create() {
  if (!fs.existsSync(dataDir)) throw new Error(`no data directory at ${dataDir} — nothing to back up`);

  const { snapshot, warnings } = createSnapshot(dataDir);
  const stamp = snapshot.createdAt.replace(/[:.]/g, '-').replace(/Z$/, 'Z');
  const file = path.join(backupDir, `telegraph-${stamp}.json.gz`);

  fs.mkdirSync(backupDir, { recursive: true });
  const bytes = serialize(snapshot);
  fs.writeFileSync(file, bytes);

  // Read it back and verify it from disk, not from memory. A backup that was
  // only ever checked as an in-memory object has not tested the one thing that
  // can actually fail here: that the bytes reached the platter intact.
  const check = verify(parse(fs.readFileSync(file)));
  if (!check.ok) {
    fs.rmSync(file, { force: true });
    throw new Error(`the backup did not survive a read-back and has been deleted:\n  - ${check.problems.join('\n  - ')}`);
  }

  const s = snapshot.summary;
  console.log(`\n  ✓ ${path.relative(process.cwd(), file)}  (${(bytes.length / 1024).toFixed(1)} KB)`);
  console.log(`    ${s.agents} agents · ${s.mailboxes} mailboxes · ${s.queuedWires} queued wires · ${s.files} files`);
  console.log(`    verified by read-back: every file matches its checksum`);
  for (const w of warnings) console.log(`\n    ! ${w}`);

  const kept = prune(Number(opt('keep', env.TELEGRAPH_BACKUP_KEEP ?? 30)));
  if (kept.pruned.length) console.log(`\n    pruned ${kept.pruned.length} old backup(s), keeping the newest ${kept.keep}`);
  console.log();
}

function prune(keep) {
  const all = backups();
  if (!Number.isFinite(keep) || keep <= 0 || all.length <= keep) return { pruned: [], keep };
  const pruned = all.slice(keep);
  for (const b of pruned) fs.rmSync(b.file, { force: true });
  return { pruned, keep };
}

// --- list -------------------------------------------------------------------
function backups() {
  if (!fs.existsSync(backupDir)) return [];
  return fs.readdirSync(backupDir)
    .filter((f) => f.startsWith('telegraph-') && f.endsWith('.json.gz'))
    .map((f) => ({ file: path.join(backupDir, f), name: f, size: fs.statSync(path.join(backupDir, f)).size }))
    .sort((a, b) => b.name.localeCompare(a.name)); // ISO stamps sort lexically = newest first
}

function list() {
  const all = backups();
  if (!all.length) {
    console.log(`\n  no backups in ${backupDir} — run \`npm run backup\`\n`);
    return;
  }
  console.log(`\n  ${all.length} backup(s) in ${backupDir}, newest first:\n`);
  for (const b of all) console.log(`    ${b.name}  ${(b.size / 1024).toFixed(1)} KB`);
  console.log();
}

// Resolve a backup argument: an explicit path, or `latest`/nothing for the newest.
function pick(arg) {
  if (!arg || arg === 'latest') {
    const all = backups();
    if (!all.length) throw new Error(`no backups in ${backupDir}`);
    return all[0].file;
  }
  const file = path.resolve(arg);
  if (!fs.existsSync(file)) throw new Error(`no such backup: ${file}`);
  return file;
}

// --- verify -----------------------------------------------------------------
function doVerify() {
  const file = pick(args[0]);
  const snapshot = parse(fs.readFileSync(file));
  const check = verify(snapshot);
  const s = snapshot.summary ?? {};

  console.log(`\n  ${path.basename(file)}`);
  console.log(`    taken:    ${snapshot.createdAt}`);
  console.log(`    contents: ${s.agents ?? '?'} agents · ${s.mailboxes ?? '?'} mailboxes · ${s.queuedWires ?? '?'} queued wires`);
  if (snapshot.torn) {
    console.log(`    note:     taken while the relay was writing; may mix files from either side of a write`);
  }
  if (check.ok) {
    console.log(`\n  ✓ intact — all ${Object.keys(snapshot.files).length} files match their checksums and parse as JSON\n`);
    return;
  }
  console.log(`\n  ✗ DAMAGED:`);
  for (const p of check.problems) console.log(`    - ${p}`);
  console.log();
  process.exitCode = 1;
}

// --- restore ----------------------------------------------------------------
async function doRestore() {
  const file = pick(args[0]);
  const snapshot = parse(fs.readFileSync(file));
  const dryRun = flags.has('--dry-run');

  // Refuse under a live relay. This is not caution, it's correctness: storage.js
  // holds the whole dataset in memory and rewrites each file wholesale, so a
  // running relay's next write would quietly revert the restore — and you'd walk
  // away believing the data was back.
  if (await relayIsLive(port)) {
    throw new Error(
      `a relay is answering on port ${port}. Stop it before restoring — it holds the data set in\n` +
      `    memory and would overwrite the restored files with its own stale copy on the next write.`
    );
  }

  const plan = restore(snapshot, dataDir, { dryRun: true });
  console.log(`\n  restore ${path.basename(file)} → ${dataDir}`);
  console.log(`    taken:   ${snapshot.createdAt}`);
  console.log(`    writes:  ${plan.written.length} file(s)`);
  console.log(`    removes: ${plan.removed.length} file(s) not present in the backup${plan.removed.length ? ':' : ''}`);
  for (const r of plan.removed) console.log(`             - ${r}`);

  if (dryRun) {
    console.log(`\n  (--dry-run: nothing written)\n`);
    return;
  }

  // Snapshot what's there now, before we overwrite it. Restoring the wrong
  // backup is a normal human error and it must not be a one-way door.
  if (fs.existsSync(dataDir)) {
    const { snapshot: current } = createSnapshot(dataDir);
    fs.mkdirSync(backupDir, { recursive: true });
    const safety = path.join(backupDir, `pre-restore-${current.createdAt.replace(/[:.]/g, '-')}.json.gz`);
    fs.writeFileSync(safety, serialize(current));
    console.log(`\n    current data saved first → ${path.relative(process.cwd(), safety)}`);
  }

  if (!flags.has('--yes') && process.stdin.isTTY) {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise((res) => rl.question(`\n  Overwrite ${dataDir} with this backup? [y/N] `, res));
    rl.close();
    if (!/^y(es)?$/i.test(answer.trim())) {
      console.log('\n  aborted — nothing written\n');
      return;
    }
  }

  const done = restore(snapshot, dataDir);
  console.log(`\n  ✓ restored ${done.written.length} file(s), removed ${done.removed.length}`);
  console.log('\n' + RESTORE_NOTES.split('\n').map((l) => '    ' + l).join('\n'));
  console.log(`\n    Now start the relay:  npm run serve\n`);
}

function readDotEnv(file) {
  if (!fs.existsSync(file)) return {};
  const out = {};
  for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
    const m = /^\s*(?:export\s+)?([A-Z0-9_]+)\s*=\s*(.*)\s*$/.exec(line);
    if (m) out[m[1]] = m[2].replace(/^["']|["']$/g, '');
  }
  return out;
}
