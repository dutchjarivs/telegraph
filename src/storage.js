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
    fs.mkdirSync(this.mailboxDir, { recursive: true });
    fs.mkdirSync(this.sentDir, { recursive: true });
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
