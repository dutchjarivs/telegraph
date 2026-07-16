// Snapshot and restore the relay's data directory.
//
// What's actually irreplaceable here is narrow but severe: `billing.json` holds
// credits people paid real money for, and `agents.json` is the directory. Mail
// in flight is undelivered mail — nobody else has a copy. Lose the disk today
// and there is no way to reconstruct any of it. So: a snapshot you can take
// while the relay runs, and a restore that refuses to do anything clever.
//
// The format is one gzipped JSON document, not a tarball. Every file the relay
// owns is already JSON text, so a backup that is itself readable JSON can be
// inspected, diffed, and checksum-verified with nothing but `zcat` and eyes —
// which is what you want at 3am when the thing you're restoring *is* the tool
// you'd otherwise use to read the backup.
//
// Secrets are deliberately NOT included. See collectFiles().
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';
import crypto from 'node:crypto';

export const BACKUP_FORMAT = 'telegraph-backup';
export const BACKUP_VERSION = 1;

// Top-level files the relay owns. An explicit allowlist, not a directory sweep:
// an interrupted atomicWrite() leaves a `.tmp` sibling behind, and a sweep would
// happily snapshot that half-written file next to its own complete original.
const TOP_LEVEL = [
  'agents.json',
  'billing.json',
  'payments.json',
  'reports.json',
  'moderation.json',
  'blocks.json',
  // Spam controls and the operator audit trail are relay-owned data with no
  // secrets in them — omitting them from a snapshot silently reverts users'
  // allowlists/quotas on restore and loses the compliance log entirely.
  'allowlist.json',
  'quotas.json',
  'quota-counts.json', // today's per-sender delivery counts (keeps quotas honest across a restore)
  'audit.json',
];

// Deliberately NOT backed up, even though it is in dataDir: `webhooks.json`
// stores each agent's per-hook HMAC secret. The whole no-secrets-in-a-backup
// stance (see EXCLUDED_SECRETS) is that a backup gets copied around, so it must
// not carry anything that is a key. A webhook secret is a lesser key than the
// admin token, but it is still one — so webhook registrations, like the admin
// token, are re-established after a recovery rather than shipped in the file.
// (This is moot until webhooks deploy; documented now so it isn't "fixed" later
// by blindly adding the file.)
export const NOT_BACKED_UP = ['webhooks.json'];

// Per-address files live in these subdirectories. `.seen.json` lives in
// mailboxes/ alongside the mailbox itself and is included: it's the replay
// guard, and restoring mailboxes without it would reopen the window where an
// old envelope can be re-delivered — and its sender re-charged. `idempotency/`
// (per-sender send-dedup ledgers) and `receipts/` (delivery receipts) are the
// same class of per-address JSON and restore alongside the mailboxes they guard.
const SUBDIRS = ['mailboxes', 'sent', 'idempotency', 'receipts'];

// Never in a backup, by design:
//   .env, .admin-token, .stripe-webhook-secret
// They aren't in dataDir, so no code here can reach them — but say it out loud,
// because "back up everything" is the obvious instinct and it's the wrong one.
// A backup gets copied to laptops, object storage, and chat threads. A backup
// that carries the admin token turns every one of those copies into a key to
// the relay. Those three files are small, they change ~never, and they belong
// in a password manager. RESTORE_NOTES says so where an operator will read it.
export const EXCLUDED_SECRETS = ['.env', '.admin-token', '.stripe-webhook-secret'];

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// Relative paths of every relay-owned file present in dataDir.
function collectFiles(dataDir) {
  const files = [];
  for (const name of TOP_LEVEL) {
    if (fs.existsSync(path.join(dataDir, name))) files.push(name);
  }
  for (const dir of SUBDIRS) {
    const abs = path.join(dataDir, dir);
    if (!fs.existsSync(abs)) continue;
    for (const name of fs.readdirSync(abs).sort()) {
      // .tmp siblings are in-flight atomicWrite()s, not data.
      if (!name.endsWith('.json')) continue;
      files.push(`${dir}/${name}`);
    }
  }
  return files;
}

// A fingerprint of the on-disk state, used to detect a torn read (below).
function fingerprint(dataDir, files) {
  return files.map((rel) => {
    try {
      const st = fs.statSync(path.join(dataDir, rel));
      return `${rel}:${st.mtimeMs}:${st.size}`;
    } catch {
      return `${rel}:absent`;
    }
  }).join('|');
}

// Take a snapshot, optionally while the relay is serving traffic.
//
// Every individual file is safe to read at any moment: storage.js only ever
// writes via write-tmp-then-rename, so a reader sees the whole old file or the
// whole new one, never a half. The hazard is at the *set* level — file A read
// before a wire lands, file B read after — which would capture a mailbox
// holding a wire the sender's meter has no record of.
//
// So: fingerprint the tree, read it, fingerprint again, and retry if anything
// moved underneath us. On a relay this size the read takes milliseconds and the
// first attempt nearly always wins. If it never converges (a genuinely busy
// relay), we still return the snapshot and flag it torn, because a snapshot
// with a known-fuzzy edge is worth incomparably more than no snapshot at all —
// and the operator deserves to be told which one they got.
export function createSnapshot(dataDir, { attempts = 5, now = () => new Date() } = {}) {
  const warnings = [];
  let files = [];
  let contents = {};
  let torn = true;

  for (let i = 0; i < attempts; i++) {
    files = collectFiles(dataDir);
    const before = fingerprint(dataDir, files);
    contents = {};
    let vanished = false;
    for (const rel of files) {
      try {
        contents[rel] = fs.readFileSync(path.join(dataDir, rel), 'utf8');
      } catch (err) {
        // A mailbox can legitimately be deleted mid-read (removeAgent, or an
        // expiry sweep). That's not corruption — it's just a stale file list.
        if (err.code !== 'ENOENT') throw err;
        vanished = true;
        break;
      }
    }
    if (!vanished && fingerprint(dataDir, files) === before) {
      torn = false;
      break;
    }
  }

  if (torn) {
    warnings.push(
      'the relay wrote to its data directory while this snapshot was being taken, and the ' +
      'snapshot did not converge after ' + attempts + ' attempts — it may mix files from either ' +
      'side of a write. It is still a usable backup; for a provably clean one, stop the relay first.'
    );
  }

  const digests = {};
  for (const [rel, text] of Object.entries(contents)) digests[rel] = sha256(Buffer.from(text, 'utf8'));

  // Cheap sanity read of the payload, so the *backup* is the thing that notices
  // pre-existing corruption rather than the restore six weeks from now.
  for (const [rel, text] of Object.entries(contents)) {
    try {
      JSON.parse(text);
    } catch {
      warnings.push(`${rel} is not valid JSON on disk — backing it up verbatim, but the relay cannot read it either`);
    }
  }

  const snapshot = {
    format: BACKUP_FORMAT,
    version: BACKUP_VERSION,
    createdAt: now().toISOString(),
    torn,
    // Counts are for the human reading `backup verify`, not for the restore
    // path, which trusts nothing and recomputes everything.
    summary: {
      files: files.length,
      agents: countKeys(contents['agents.json']),
      mailboxes: files.filter((f) => f.startsWith('mailboxes/') && !f.endsWith('.seen.json')).length,
      queuedWires: files
        .filter((f) => f.startsWith('mailboxes/') && !f.endsWith('.seen.json'))
        .reduce((n, f) => n + countArray(contents[f]), 0),
    },
    excludedSecrets: EXCLUDED_SECRETS,
    excludedData: NOT_BACKED_UP, // relay-owned but omitted on purpose (carries per-hook secrets)
    sha256: digests,
    files: contents,
  };
  return { snapshot, warnings };
}

const countKeys = (text) => {
  try { return Object.keys(JSON.parse(text)).length; } catch { return 0; }
};
const countArray = (text) => {
  try { const v = JSON.parse(text); return Array.isArray(v) ? v.length : 0; } catch { return 0; }
};

export function serialize(snapshot) {
  return zlib.gzipSync(Buffer.from(JSON.stringify(snapshot, null, 2), 'utf8'), { level: 9 });
}

// Parse a backup file. Throws with a plain-language reason rather than letting
// a zlib or JSON error surface raw — the operator running this has already had
// a bad day.
export function parse(buf) {
  let text;
  try {
    text = zlib.gunzipSync(buf).toString('utf8');
  } catch {
    throw new Error('not a gzip file — is this a Telegraph backup?');
  }
  let snapshot;
  try {
    snapshot = JSON.parse(text);
  } catch {
    throw new Error('backup is gzipped but its contents are not JSON — the file is damaged');
  }
  if (snapshot?.format !== BACKUP_FORMAT) {
    throw new Error(`not a Telegraph backup (format: ${JSON.stringify(snapshot?.format ?? null)})`);
  }
  if (snapshot.version > BACKUP_VERSION) {
    throw new Error(
      `backup is version ${snapshot.version}, this build understands up to ${BACKUP_VERSION} — ` +
      'upgrade Telegraph before restoring, rather than letting an older build guess at a newer format'
    );
  }
  if (!snapshot.files || typeof snapshot.files !== 'object') {
    throw new Error('backup has no files section — the file is damaged');
  }
  return snapshot;
}

// Check a snapshot against its own checksums. This is the whole point of having
// them: a backup nobody has ever verified is a rumour, not a backup.
export function verify(snapshot) {
  const problems = [];
  const digests = snapshot.sha256 ?? {};
  for (const [rel, text] of Object.entries(snapshot.files)) {
    if (!Object.hasOwn(digests, rel)) {
      problems.push(`${rel}: no checksum recorded`);
      continue;
    }
    if (sha256(Buffer.from(text, 'utf8')) !== digests[rel]) {
      problems.push(`${rel}: checksum mismatch — contents do not match what was backed up`);
    }
    try {
      JSON.parse(text);
    } catch {
      problems.push(`${rel}: not valid JSON`);
    }
  }
  for (const rel of Object.keys(digests)) {
    if (!Object.hasOwn(snapshot.files, rel)) problems.push(`${rel}: checksummed but missing from the backup`);
  }
  return { ok: problems.length === 0, problems };
}

// Guard against a backup whose paths try to escape dataDir. A backup file is
// an input like any other — it can arrive by scp from somewhere you don't
// control — and "restore" that writes ../../.ssh/authorized_keys is how a
// disaster-recovery tool becomes the disaster.
function safeTarget(dataDir, rel) {
  const abs = path.resolve(dataDir, rel);
  const root = path.resolve(dataDir);
  if (abs !== root && !abs.startsWith(root + path.sep)) {
    throw new Error(`backup contains a path that escapes the data directory: ${rel}`);
  }
  const allowed = TOP_LEVEL.includes(rel) ||
    (SUBDIRS.some((d) => rel.startsWith(`${d}/`)) && rel.endsWith('.json') && !rel.slice(rel.indexOf('/') + 1).includes('/'));
  if (!allowed) throw new Error(`backup contains a file the relay does not own: ${rel}`);
  return abs;
}

// Write a snapshot into dataDir.
//
// Deliberately NOT a merge. A restore is "make the relay be as it was at time
// T", and a half-restore — new balances, old mailboxes — is a state that never
// existed and that nobody has reasoned about. Files the relay owns that aren't
// in the backup are removed, because at time T they did not exist, and leaving
// a stale mailbox behind would resurrect wires the recipient already acked.
export function restore(snapshot, dataDir, { dryRun = false } = {}) {
  const check = verify(snapshot);
  if (!check.ok) {
    throw new Error(`refusing to restore a backup that fails verification:\n  - ${check.problems.join('\n  - ')}`);
  }

  const targets = new Map();
  for (const [rel, text] of Object.entries(snapshot.files)) targets.set(rel, safeTarget(dataDir, rel));

  const existing = fs.existsSync(dataDir) ? collectFiles(dataDir) : [];
  const removed = existing.filter((rel) => !targets.has(rel));
  const written = [...targets.keys()].sort();

  if (dryRun) return { written, removed, dryRun: true };

  for (const dir of SUBDIRS) fs.mkdirSync(path.join(dataDir, dir), { recursive: true });
  for (const [rel, abs] of targets) {
    const tmp = abs + '.tmp';
    fs.writeFileSync(tmp, snapshot.files[rel]);
    fs.renameSync(tmp, abs);
  }
  for (const rel of removed) fs.rmSync(path.join(dataDir, rel), { force: true });

  return { written, removed, dryRun: false };
}

// Is a relay serving out of this data directory right now?
//
// This matters more than it looks. storage.js reads every JSON file into memory
// once, at construction, and every write serialises that in-memory object back
// over the whole file. So a restore under a live relay isn't merely racy — the
// relay's next write silently reverts it, and you are left believing you have
// restored data that is already gone again. Refusing is the correct behaviour,
// not an abundance of caution.
export async function relayIsLive(port, { fetchImpl = fetch, timeoutMs = 2000 } = {}) {
  try {
    const res = await fetchImpl(`http://127.0.0.1:${port}/v1/health`, {
      signal: AbortSignal.timeout(timeoutMs),
    });
    return res.ok;
  } catch {
    return false;
  }
}

export const RESTORE_NOTES = `
Secrets are not in this backup, on purpose: .env, .admin-token and
.stripe-webhook-secret never enter it. Backups get copied around; a backup
carrying the admin token makes every copy a key to the relay. Keep those three
in a password manager — they are small and they almost never change.

Webhook registrations (webhooks.json) are also omitted: each carries a per-hook
HMAC secret, and the same "a backup must not be a key" rule applies. After a
recovery, agents re-register their webhooks (POST /v1/webhook) — a new secret is
issued and push delivery resumes.

A full recovery is therefore: restore this backup, put those three files back,
then start the relay.
`.trim();
