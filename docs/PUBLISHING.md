# Publishing the npm packages

Telegraph ships two public npm packages from this repo:

- **`@telegraphnet/sdk`** — the JS/TS SDK (`sdk/js/`)
- **`@telegraphnet/cli`** — the command-line client (`cli/`), which depends on the SDK

Both are built, tested, and publish-ready. As of **2026-07-14** publishing is
**blocked** on one thing (see below); once that's fixed, publishing is two
commands.

## ⚠ Current blocker (2026-07-14)

`npm publish` returns `403 — a granular access token with "bypass 2FA" is
required`. The `telegraph-publish` token in `~/.npmrc` authenticates reads
(`npm whoami` → `telegraphnet`) but lacks publish permission. The
`.npm-account/credentials.json` note claims it has bypass-2FA; the actual token
on npmjs.com does not.

**Fix (Tristan):** log in to npmjs.com as `telegraphnet` (OTP goes to
dutch.jarvis@gmail.com), and either edit the token's permissions to enable
"bypass 2FA" / automation, or regenerate it with read/write + bypass-2FA and
update `~/.npmrc` (`npm config set //registry.npmjs.org/:_authToken <new>`) plus
the two credential files. Then follow the steps below.

## Publish steps (once the token is fixed)

```bash
cd telegraph

# 1. Confirm you're the right npm user.
npm whoami            # → telegraphnet

# 2. Safety gate: inspect exactly what each tarball will contain. Publishing a
#    secret is unrecoverable, so this fails if anything sensitive is present.
npm run publish:check

# 3. Full test suite green (includes the SDK's own tests).
npm test              # → pass N, fail 0

# 4. Publish the SDK first (the CLI depends on it).
cd sdk/js && npm publish --access public && cd ../..

# 5. Publish the CLI.
cd cli && npm publish --access public && cd ..

# 6. Verify.
npm view @telegraphnet/sdk version
npm view @telegraphnet/cli version
```

## After publishing

- Remove the "📦 Package status" banner from `docs/INTEGRATIONS.md` (the
  `npm install @telegraphnet/...` lines then work as written).
- The published `v0.1.0` reflects the **currently-deployed** relay's feature set.
  Features added to `main` since (idempotency keys, allowlists, delivery
  receipts, dashboard metrics/audit) are **not** in the published SDK/CLI and are
  marked "⚠ Unreleased" in `docs/PROTOCOL.md`. When the relay is next deployed
  with those, bump the SDK/CLI to `0.2.0`, port the new client methods into
  `sdk/js/` (they currently live only in the repo's `src/client.js`), and publish
  again.

## Versioning note

`sdk/js/` and `cli/` are deliberately frozen at the deployed feature set so a
`v0.1.0` publish never advertises an endpoint the live relay 404s. Keep it that
way: only add a client feature to the published packages once the relay that
serves it is live.
