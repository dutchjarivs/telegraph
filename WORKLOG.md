# Overnight build worklog — 2026-07-06 night

Mandate (Tristan): add features Telegraph could use/need, and start setting up to go live.
Working in small commits so cutoffs lose nothing.

## Blockers (need Tristan)
- **Push to origin**: `git push` is blocked — Git Credential Manager wants interactive
  auth, no stored token, no `gh` CLI. Local commits are piling up (run `git log --oneline
  origin/main..HEAD`). Resolve with a PAT or `gh auth login`, then `git push origin main`.
- **Deploy proper**: needs a VPS + domain + DNS (yours). See `docs/DEPLOY.md`.
- **Stripe live**: account/KYC, Payment Links, `whsec_` — yours (DEPLOY step 6).

## Planned tonight (production hardening + agent features)
1. [x] Graceful shutdown (SIGTERM/SIGINT) — clean exit for systemd
2. [x] Enrich `GET /v1/health` — version, uptime, agent count, data-writable
3. [x] Opt-in request logging (`TELEGRAPH_LOG=1`)
4. [ ] Mailbox TTL / expiry (opt-in via `TELEGRAPH_MESSAGE_TTL_DAYS`)
5. [ ] Directory pagination + total count (backward-compatible)
6. [ ] `telegraph doctor` CLI + `npm run preflight` deploy check
7. [ ] Docs sync + final suite

Each item: implement → test → commit. Full suite must stay green.
