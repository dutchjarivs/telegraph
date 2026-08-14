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
4. [x] Mailbox TTL / expiry (opt-in via `TELEGRAPH_MESSAGE_TTL_DAYS`) — 19bf330
5. [x] Directory pagination + total count (backward-compatible) — b0693b1
6. [x] `telegraph doctor` CLI + `npm run preflight` deploy check — 9e10246
7. [x] Docs sync + final suite — finished morning of 2026-07-07 (session died overnight ~22:05)

Each item: implement → test → commit. Full suite must stay green.

---

# 2026-08-14 marketing pass — the parked-wire census audits badly

Prompted by @hermessol on Moltbook: *"If you can't construct an input that makes the
census go red, you don't have a check — you have a renderer."* Ran it against
`parkedWireStats`, which I had been describing as the independently-authored witness
that `expiredUncollected` structurally cannot be.

**Three properties it had, all measured, none of which I'd claimed honestly:**
1. **No red branch.** It returns `{mailboxes, wires, oldestReceivedAt}` and the snapshot
   adds one subtraction. Neither function contains a comparison, so no input makes it
   report a problem. The "reading" was happening in my head.
2. **No clock.** Called at exactly one site, inside `GET /v1/admin/overview`. It runs when
   an operator asks and never otherwise — independent of the mailbox's traffic, fully
   dependent on mine. And it sits behind the admin token, so the only reader that can
   contradict the counter is unavailable to anyone who'd want it.
3. **Silent read failures, in the flattering direction.** `catch { continue }` sat one line
   above `if (empty) continue`, so an unreadable mailbox reported as an empty one.
   Measured on a copy of the live data dir — truncating the single file holding the
   oldest parked wire: `15/31/41.71 days` → `14/30/39.98 days`. The neglect metric
   *improved* because the evidence stopped being readable.

**Fixed (committed):** census now counts `unreadable` files and reports `dirUnreadable`,
surfaced in `metrics.wires.parked`. Regression test asserts the counter fires on the input
that used to be silent. Suite 334/334.

## FOUND, NOT FIXED — needs Tristan's call before it goes near the wire path

**One corrupt mailbox file 500s the recipient's inbox, every send to them, and the entire
admin overview.** `Storage.loadMailbox` (src/storage.js:446) `JSON.parse`s with no guard,
and it is on the delivery path at server.js:1114 (send), 1256/1278 (inbox, longpoll),
1343, 1443 (ack), 1877 (overview, mapped over *every* agent), 2088.

Reproduced on a scratch relay:
```
recipient inbox      -> 500 internal_error
sender send to them  -> 500 internal_error
admin overview       -> 500 internal_error   (all agents, not just the affected one)
```
The operator gets a generic `internal_error` with no address and no hint it is a disk fault.
A truncated `atomicWrite` interrupted by the crash-restart the watchdog performs is exactly
how this file state arises.

**Why I did not just swallow it:** returning `[]` on an unparseable mailbox would let the
next `saveMailbox` overwrite wires the relay merely failed to *read* — turning an
availability bug into silent data loss. The right shape is a tagged error plus a route that
refuses reads *and writes* for that address with a specific reason, which is a delivery-path
change I am not making unreviewed on a marketing pass.
