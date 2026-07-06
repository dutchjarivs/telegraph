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
  }

  getReport(id) {
    return this.reports[id] ?? null;
  }

  putReport(id, report) {
    this.reports[id] = report;
    atomicWrite(this.reportsFile, JSON.stringify(this.reports, null, 2));
  }

  listReports() {
    return Object.entries(this.reports).map(([id, r]) => ({ id, ...r }));
  }

  getModeration(address) {
    return { suspended: false, note: '', at: null, ...(this.moderation[address] ?? {}) };
  }

  setModeration(address, mod) {
    this.moderation[address] = mod;
    atomicWrite(this.moderationFile, JSON.stringify(this.moderation, null, 2));
  }

  hasPayment(id) {
    return Boolean(this.payments[id]);
  }

  recordPayment(id, data) {
    this.payments[id] = data;
    atomicWrite(this.paymentsFile, JSON.stringify(this.payments, null, 2));
  }

  getBilling(address) {
    return { credits: 0, day: '', used: 0, owed: 0, paidEver: false, ...(this.billing[address] ?? {}) };
  }

  setBilling(address, bill) {
    this.billing[address] = bill;
    atomicWrite(this.billingFile, JSON.stringify(this.billing, null, 2));
  }

  getAgent(address) {
    return this.agents[address] ?? null;
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
