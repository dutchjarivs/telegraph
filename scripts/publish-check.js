#!/usr/bin/env node
// Pre-publish safety gate for the npm packages. Publishing a secret is
// unrecoverable, so this inspects exactly what `npm pack` would ship and fails
// loudly if anything sensitive is about to leave the machine. Run it before
// every publish:
//
//   node scripts/publish-check.js
//
// Exit 0 = both tarballs are clean and ready. Exit 1 = do NOT publish.
import { execSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const PACKAGES = [
  { name: '@telegraphnet/sdk', dir: path.join(root, 'sdk', 'js') },
  { name: '@telegraphnet/cli', dir: path.join(root, 'cli') },
];

// Any packed file whose path matches one of these is a hard stop. These are the
// things that must never ship: identities/keys, env, admin/stripe secrets,
// per-deployment data, logs, and stray dotfiles.
const FORBIDDEN = [
  /identity/i,
  /\.env(\.|$)/i,
  /admin-token/i,
  /stripe/i,
  /(^|\/)data\//i,
  /(^|\/)backups\//i,
  /\.log$/i,
  /\.pem$/i,
  /\.key$/i,
  /secret/i,
  /credentials/i,
];

// What each package is expected to contain — anything outside this, flag for a
// human look (not necessarily fatal, but it shouldn't surprise us).
const EXPECTED = {
  '@telegraphnet/sdk': [/^package\.json$/, /^index\.(js|d\.ts)$/, /^mock\.(js|d\.ts)$/, /^src\//, /^README\.md$/, /^ERRORS\.md$/, /^LICENSE$/],
  '@telegraphnet/cli': [/^package\.json$/, /^bin\//, /^README\.md$/, /^LICENSE$/],
};

function packFileList(dir) {
  // `npm pack --dry-run --json` prints the exact file manifest without writing a tarball.
  const out = execSync('npm pack --dry-run --json', { cwd: dir, encoding: 'utf8' });
  const parsed = JSON.parse(out);
  const files = parsed[0]?.files ?? [];
  return files.map((f) => f.path.replace(/\\/g, '/'));
}

let failed = false;
for (const pkg of PACKAGES) {
  console.log(`\n=== ${pkg.name} ===`);
  let files;
  try {
    files = packFileList(pkg.dir);
  } catch (err) {
    console.error(`  ✗ could not run npm pack: ${err.message}`);
    failed = true;
    continue;
  }
  const forbidden = files.filter((f) => FORBIDDEN.some((re) => re.test(f)));
  if (forbidden.length) {
    console.error(`  ✗ FORBIDDEN files in tarball — DO NOT PUBLISH:`);
    for (const f of forbidden) console.error(`      ${f}`);
    failed = true;
  }
  const expected = EXPECTED[pkg.name] ?? [];
  const unexpected = files.filter((f) => !expected.some((re) => re.test(f)));
  if (unexpected.length) {
    console.warn(`  ⚠ unexpected files (review before publishing):`);
    for (const f of unexpected) console.warn(`      ${f}`);
  }
  console.log(`  ${forbidden.length ? '✗' : '✓'} ${files.length} files: ${files.join(', ')}`);
}

if (failed) {
  console.error('\n✗ publish-check FAILED — a tarball contains something it must not. Do not publish.');
  process.exit(1);
}
console.log('\n✓ publish-check passed — both tarballs contain only intended files. Safe to `npm publish --access public`.');
