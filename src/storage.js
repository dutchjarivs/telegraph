// File-backed storage: one agents.json registry + one mailbox file per address.
// Deliberately boring. Swap for SQLite/Postgres when volume demands it.
import fs from 'node:fs';
import path from 'node:path';

export class Storage {
  constructor(dataDir) {
    this.dataDir = dataDir;
    this.agentsFile = path.join(dataDir, 'agents.json');
    this.mailboxDir = path.join(dataDir, 'mailboxes');
    // Sent log: self-sealed copies of outbound wires (sender's own history).
    // The relay can't read these either — they're nacl.box'd to the sender.
    this.sentDir = path.join(dataDir, 'sent');
    // Idempotency ledger, one file per *sender*: { key: {id, at} }. A client
    // that retries a send with the same key (e.g. after a network blip that
    // dropped the response) gets the original wire's id back instead of a
    // second delivery and a second charge. Keyed by sender because the sender
    // chooses the key; distinct from the recipient-keyed `seen` replay ledger.
    this.idempotencyDir = path.join(dataDir, 'idempotency');
    // Delivery receipts, one file per *sender*: the recipient-signed proofs that
    // a wire this sender sent was fetched and acked. Kept under the sender
    // because the sender is who reads them (GET /v1/receipts).
    this.receiptsDir = path.join(dataDir, 'receipts');
    fs.mkdirSync(this.mailboxDir, { recursive: true });
    fs.mkdirSync(this.sentDir, { recursive: true });
    fs.mkdirSync(this.idempotencyDir, { recursive: true });
    fs.mkdirSync(this.receiptsDir, { recursive: true });
    this.agents = fs.existsSync(this.agentsFile)
      ? JSON.parse(fs.readFileSync(this.agentsFile, 'utf8'))
      : {};
    // Billing lives in its own file: agent records are public, balances are not.
    this.billingFile = path.join(dataDir, 'billing.json');
    this.billing = fs.existsSync(this.billingFile)
      ? JSON.parse(fs.readFileSync(this.billingFile, 'utf8'))
      : {};
    // Payment ledger: processed checkout sessions, for idempotency + audit.
    this.paymentsFile = path.join(dataDir, 'payments.json');
    this.payments = fs.existsSync(this.paymentsFile)
      ? JSON.parse(fs.readFileSync(this.paymentsFile, 'utf8'))
      : {};
    // Abuse reports: keyed by report id (reporter × message), kept even after
    // the reported agent is removed — reputation follows the keypair.
    this.reportsFile = path.join(dataDir, 'reports.json');
    this.reports = fs.existsSync(this.reportsFile)
      ? JSON.parse(fs.readFileSync(this.reportsFile, 'utf8'))
      : {};
    // Moderation state (suspensions), separate from the public agent record so
    // a re-register (which rewrites the record) can never clear it.
    this.moderationFile = path.join(dataDir, 'moderation.json');
    this.moderation = fs.existsSync(this.moderationFile)
      ? JSON.parse(fs.readFileSync(this.moderationFile, 'utf8'))
      : {};
    // Personal block lists: { blockerAddress: { blockedAddress: {at, note} } }.
    // Distinct from moderation — that's the operator's call on an agent's right
    // to send at all; this is one agent's own doorbell. Keyed by address, so a
    // block follows the keypair through removal and re-registration.
    this.blocksFile = path.join(dataDir, 'blocks.json');
    this.blocks = fs.existsSync(this.blocksFile)
      ? JSON.parse(fs.readFileSync(this.blocksFile, 'utf8'))
      : {};
    // Recipient allowlists: { recipient: { mode: bool, entries: {address: {at, note}} } }.
    // The opt-in inverse of the block list — when mode is on, ONLY listed
    // senders get through. Like blocks, keyed by address so it follows the
    // keypair. A recipient builds the list first, then flips mode on, so
    // turning it on never silently drops mail from someone not yet added.
    this.allowlistFile = path.join(dataDir, 'allowlist.json');
    this.allowlist = fs.existsSync(this.allowlistFile)
      ? JSON.parse(fs.readFileSync(this.allowlistFile, 'utf8'))
      : {};
    // Per-sender quotas: { recipient: { perSenderDailyMax: N } }.
    // When N > 0, the relay rejects wires from a non-allowlisted sender
    // after they've already delivered N wires to this recipient today.
    // Allowlisted senders are exempt (they're explicitly trusted). 0 = unlimited.
    this.quotasFile = path.join(dataDir, 'quotas.json');
    this.quotas = fs.existsSync(this.quotasFile)
      ? JSON.parse(fs.readFileSync(this.quotasFile, 'utf8'))
      : {};
    // Daily delivery counters for quota enforcement:
    // { "2026-07-14": { fromAddr: { toAddr: count } } }. Old days are pruned
    // on access. Counts are per-delivery (not per-attempt) so a rejected wire
    // never burns a sender's quota.
    this.quotaCountsFile = path.join(dataDir, 'quota-counts.json');
    this.quotaCounts = fs.existsSync(this.quotaCountsFile)
      ? JSON.parse(fs.readFileSync(this.quotaCountsFile, 'utf8'))
      : {};
    // Append-only audit trail of operator (admin-token) mutations: grants,
    // suspensions, removals, report resolutions. Separate from everything else
    // because it answers a different question — "who changed what, when, from
    // where" — and must survive even when the thing it describes is later
    // deleted. Never records secrets (no token, no balances beyond the delta).
    this.auditFile = path.join(dataDir, 'audit.json');
    this.audit = fs.existsSync(this.auditFile)
      ? JSON.parse(fs.readFileSync(this.auditFile, 'utf8'))
      : [];
  }

  // Append an operator action. Capped as a ring buffer so the file can't grow
  // without bound; the cap is high enough that admin actions never realistically
  // roll off, and `truncated` on read tells a viewer if any ever did.
  appendAudit(entry, cap = 10_000) {
    this.audit.push(entry);
    if (this.audit.length > cap) this.audit = this.audit.slice(-cap);
    atomicWrite(this.auditFile, JSON.stringify(this.audit, null, 2));
  }

  // Most recent operator actions, newest first (bounded slice for the dashboard).
  listAudit(limit = 100) {
    const n = this.audit.length;
    const slice = limit && limit < n ? this.audit.slice(n - limit) : this.audit.slice();
    return slice.reverse();
  }

  auditCount() {
    return this.audit.length;
  }

  // hasOwn throughout: a bare lookup on "__proto__" or "constructor" would
  // otherwise resolve to a prototype member and report a block that isn't there.
  getBlocks(blocker) {
    return Object.hasOwn(this.blocks, blocker) ? this.blocks[blocker] : {};
  }

  isBlocked(blocker, sender) {
    const list = this.getBlocks(blocker);
    return Object.hasOwn(list, sender);
  }

  setBlock(blocker, blocked, entry) {
    const list = this.getBlocks(blocker);
    list[blocked] = entry;
    this.blocks[blocker] = list;
    atomicWrite(this.blocksFile, JSON.stringify(this.blocks, null, 2));
  }

  removeBlock(blocker, blocked) {
    const list = this.getBlocks(blocker);
    if (!Object.hasOwn(list, blocked)) return false;
    delete list[blocked];
    if (Object.keys(list).length) this.blocks[blocker] = list;
    else delete this.blocks[blocker];
    atomicWrite(this.blocksFile, JSON.stringify(this.blocks, null, 2));
    return true;
  }

  // hasOwn throughout, same prototype-safety reason as blocks above.
  getAllowlist(recipient) {
    const a = Object.hasOwn(this.allowlist, recipient) ? this.allowlist[recipient] : {};
    return { mode: a.mode === true, entries: a.entries && typeof a.entries === 'object' ? a.entries : {} };
  }

  // When mode is off, everyone is allowed (the list is dormant). When on, only
  // listed senders pass. A recipient never allowlist-blocks their own address.
  isAllowed(recipient, sender) {
    if (sender === recipient) return true;
    const { mode, entries } = this.getAllowlist(recipient);
    if (!mode) return true;
    return Object.hasOwn(entries, sender);
  }

  setAllowEntry(recipient, address, entry) {
    const cur = this.getAllowlist(recipient);
    cur.entries[address] = entry;
    this.allowlist[recipient] = { mode: cur.mode, entries: cur.entries };
    atomicWrite(this.allowlistFile, JSON.stringify(this.allowlist, null, 2));
  }

  removeAllowEntry(recipient, address) {
    const cur = this.getAllowlist(recipient);
    if (!Object.hasOwn(cur.entries, address)) return false;
    delete cur.entries[address];
    this.allowlist[recipient] = { mode: cur.mode, entries: cur.entries };
    atomicWrite(this.allowlistFile, JSON.stringify(this.allowlist, null, 2));
    return true;
  }

  setAllowMode(recipient, mode) {
    const cur = this.getAllowlist(recipient);
    this.allowlist[recipient] = { mode: mode === true, entries: cur.entries };
    atomicWrite(this.allowlistFile, JSON.stringify(this.allowlist, null, 2));
  }

  // --- Per-sender quotas ---
  // A recipient caps how many wires/day any single non-allowlisted sender can
  // deliver. Allowlisted senders are exempt. 0 (or absent) = unlimited.
  getQuota(recipient) {
    const q = Object.hasOwn(this.quotas, recipient) ? this.quotas[recipient] : {};
    return { perSenderDailyMax: Number.isFinite(q.perSenderDailyMax) ? q.perSenderDailyMax : 0 };
  }

  setQuota(recipient, max) {
    const n = Math.max(0, Math.floor(Number(max) || 0));
    this.quotas[recipient] = { perSenderDailyMax: n };
    atomicWrite(this.quotasFile, JSON.stringify(this.quotas, null, 2));
    return n;
  }

  // How many wires has this sender delivered to this recipient today?
  // Counts are pruned to today only on each access (cheap, keeps the file small).
  todaySenderCount(from, to) {
    const today = new Date().toISOString().slice(0, 10);
    // Prune old days lazily — keep only today.
    for (const day of Object.keys(this.quotaCounts)) {
      if (day !== today) delete this.quotaCounts[day];
    }
    const d = this.quotaCounts[today] || {};
    const fromMap = Object.hasOwn(d, from) ? d[from] : {};
    return Object.hasOwn(fromMap, to) ? fromMap[to] : 0;
  }

  // Increment today's delivery count for a (from, to) pair. Called only after a
  // wire has passed all checks and is committed to the mailbox.
  bumpSenderCount(from, to) {
    const today = new Date().toISOString().slice(0, 10);
    if (!Object.hasOwn(this.quotaCounts, today)) {
      // Lazy prune: drop old days when first touching today.
      this.quotaCounts = { [today]: {} };
    }
    if (!Object.hasOwn(this.quotaCounts[today], from)) this.quotaCounts[today][from] = {};
    const cur = this.quotaCounts[today][from][to] || 0;
    this.quotaCounts[today][from][to] = cur + 1;
    atomicWrite(this.quotaCountsFile, JSON.stringify(this.quotaCounts, null, 2));
  }

  getReport(id) {
    return Object.hasOwn(this.reports, id) ? this.reports[id] : null;
  }

  putReport(id, report) {
    this.reports[id] = report;
    atomicWrite(this.reportsFile, JSON.stringify(this.reports, null, 2));
  }

  listReports() {
    return Object.entries(this.reports).map(([id, r]) => ({ id, ...r }));
  }

  getModeration(address) {
    const mod = Object.hasOwn(this.moderation, address) ? this.moderation[address] : {};
    return { suspended: false, note: '', at: null, ...mod };
  }

  setModeration(address, mod) {
    this.moderation[address] = mod;
    atomicWrite(this.moderationFile, JSON.stringify(this.moderation, null, 2));
  }

  hasPayment(id) {
    return Object.hasOwn(this.payments, id);
  }

  recordPayment(id, data) {
    this.payments[id] = data;
    atomicWrite(this.paymentsFile, JSON.stringify(this.payments, null, 2));
  }

  getBilling(address) {
    const bill = Object.hasOwn(this.billing, address) ? this.billing[address] : {};
    // Prepaid model: free daily allowance (day/used) + prepaid credits. No tab.
    return { credits: 0, day: '', used: 0, ...bill };
  }

  setBilling(address, bill) {
    this.billing[address] = bill;
    atomicWrite(this.billingFile, JSON.stringify(this.billing, null, 2));
  }

  getAgent(address) {
    return Object.hasOwn(this.agents, address) ? this.agents[address] : null;
  }

  findByHandle(handle) {
    const h = handle.toLowerCase();
    return Object.values(this.agents).find((a) => a.handle.toLowerCase() === h) ?? null;
  }

  upsertAgent(agent) {
    this.agents[agent.address] = agent;
    atomicWrite(this.agentsFile, JSON.stringify(this.agents, null, 2));
  }

  // Operator removal: deletes the registration, its balance, and any queued
  // mail. The keypair still exists client-side — the agent can re-register.
  // Reports and moderation state are deliberately kept: the address derives
  // from the key, so re-registering brings the same reputation (and any
  // suspension) right back. Removal is not an escape hatch.
  removeAgent(address) {
    const agent = this.agents[address] ?? null;
    if (!agent) return null;
    delete this.agents[address];
    atomicWrite(this.agentsFile, JSON.stringify(this.agents, null, 2));
    if (this.billing[address]) {
      delete this.billing[address];
      atomicWrite(this.billingFile, JSON.stringify(this.billing, null, 2));
    }
    const mailbox = this.mailboxFile(address);
    if (fs.existsSync(mailbox)) fs.rmSync(mailbox);
    const seen = this.seenFile(address);
    if (fs.existsSync(seen)) fs.rmSync(seen);
    const sent = this.sentFile(address);
    if (fs.existsSync(sent)) fs.rmSync(sent);
    const idem = this.idempotencyFile(address);
    if (fs.existsSync(idem)) fs.rmSync(idem);
    const receipts = this.receiptsFile(address);
    if (fs.existsSync(receipts)) fs.rmSync(receipts);
    return agent;
  }

  sentFile(address) {
    return path.join(this.sentDir, address.replace(/[^A-Za-z0-9-]/g, '') + '.json');
  }

  loadSent(address) {
    const file = this.sentFile(address);
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : [];
  }

  // Ring buffer: oldest entries roll off past the cap. This is a convenience
  // history, not the delivery path, so dropping old copies loses nothing live.
  appendSent(address, entry, cap) {
    const log = this.loadSent(address);
    log.push(entry);
    while (log.length > cap) log.shift();
    atomicWrite(this.sentFile(address), JSON.stringify(log, null, 2));
  }

  listAgents() {
    return Object.values(this.agents);
  }

  listPayments() {
    return Object.entries(this.payments).map(([id, p]) => ({ id, ...p }));
  }

  mailboxFile(address) {
    return path.join(this.mailboxDir, address.replace(/[^A-Za-z0-9-]/g, '') + '.json');
  }

  // Delivered-wire ids per recipient ({id: deliveredAt}), kept beyond ack so a
  // replayed envelope can't re-deliver (and re-charge the sender) after the
  // recipient clears their mailbox. Persisted so a relay restart doesn't
  // reopen the window; entries are pruned once the wire's ts window has
  // passed and the envelope can no longer be replayed anyway.
  seenFile(address) {
    return path.join(this.mailboxDir, address.replace(/[^A-Za-z0-9-]/g, '') + '.seen.json');
  }

  loadSeen(address) {
    const file = this.seenFile(address);
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  }

  saveSeen(address, seen) {
    atomicWrite(this.seenFile(address), JSON.stringify(seen));
  }

  // Per-sender idempotency ledger. Same disk-name sanitisation as mailboxes.
  idempotencyFile(address) {
    return path.join(this.idempotencyDir, address.replace(/[^A-Za-z0-9-]/g, '') + '.json');
  }

  loadIdempotency(address) {
    const file = this.idempotencyFile(address);
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
  }

  saveIdempotency(address, obj) {
    atomicWrite(this.idempotencyFile(address), JSON.stringify(obj));
  }

  receiptsFile(address) {
    return path.join(this.receiptsDir, address.replace(/[^A-Za-z0-9-]/g, '') + '.json');
  }

  loadReceipts(address) {
    const file = this.receiptsFile(address);
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : [];
  }

  // Store a receipt under the sender. Idempotent per (messageId, recipient) so a
  // re-delivered receipt doesn't double-count. Ring-buffered like the sent log.
  appendReceipt(sender, entry, cap) {
    const log = this.loadReceipts(sender);
    if (log.some((r) => r.messageId === entry.messageId && r.recipient === entry.recipient)) return false;
    log.push(entry);
    while (log.length > cap) log.shift();
    atomicWrite(this.receiptsFile(sender), JSON.stringify(log, null, 2));
    return true;
  }

  loadMailbox(address) {
    const file = this.mailboxFile(address);
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : [];
  }

  saveMailbox(address, messages) {
    atomicWrite(this.mailboxFile(address), JSON.stringify(messages, null, 2));
  }
}

function atomicWrite(file, data) {
  const tmp = file + '.tmp';
  fs.writeFileSync(tmp, data);
  fs.renameSync(tmp, file);
}
