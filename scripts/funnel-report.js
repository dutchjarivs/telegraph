#!/usr/bin/env node
// Funnel report: are outsiders seeing /onboard and bailing, or never arriving?
// Reads the relay access logs (relay-live.log + relay-access-archive.log,
// written when TELEGRAPH_LOG=1) and summarizes funnel-relevant traffic by
// distinct client IP, separating fleet/local traffic from outside visitors.
//
// Usage: node scripts/funnel-report.js [--fleet-ip <ip>] [--fleet-ip-prefix <prefix>] [logfile ...]
//   --fleet-ip may repeat: exact IPs to treat as "ours" (the box the fleet runs on).
//   --fleet-ip-prefix may repeat: IP string prefixes to treat as "ours" (e.g. an
//     IPv6 /64 like "2603:90d8:201:c53:" — Windows privacy extensions rotate the
//     host part of the address per interface/session, so an exact IPv6 match
//     goes stale; a prefix match survives that rotation). Found 2026-07-28: this
//     box's own IPv6 egress was showing up as a false "outside" registration
//     because only the IPv4 fleet IP was ever passed.
//   Loopback is always treated as ours (watchdog + local health checks).
//
// Fleet identity is ALSO read from config, not just flags (2026-08-12). The flag
// alone was not enough: running the report bare — `node scripts/funnel-report.js`,
// which is how it actually gets run — silently counted 12 of this box's own rotating
// IPv6 privacy addresses as distinct external agents (external IPs 16 vs 4, discovery
// 52 vs 3, registerOk 3 vs 1). The 07-28 fix was already in the code and documented
// in this very header; the failure was that honesty was opt-in per invocation. A
// metric that only tells the truth when you remember a flag will flatter you exactly
// when you most want to believe it, because the inflated number is the comfortable
// one and nothing pushes back. So: config is loaded by default, and a run with NO
// fleet identity configured prints a loud UNCONFIGURED banner and marks the external
// numbers untrustworthy rather than printing a clean-looking lie.
//   TELEGRAPH_FLEET_IP / TELEGRAPH_FLEET_IP_PREFIX  comma-separated, either may be set.
//   scripts/funnel-fleet.local.json  {"ips": [...], "prefixes": [...]} — gitignored,
//     because a home IPv6 /64 is Tristan's address, not a project constant.
//
// Funnel stages counted per IP:
//   discovery  GET  /, /onboard, /v1/onboard, /docs/*, /README*, /directory, /v1/directory
//   register   POST /v1/register  (split by status: 2xx ok vs 4xx/5xx failed)
//   active     POST /v1/messages, GET /v1/inbox
//
// Classification (three buckets, two POSITIVE predicates + a default sink):
//   fleet         positive IP match (--fleet-ip / --fleet-ip-prefix / loopback).
//   external      positive agent-shape match on an outside IP: completed the agent
//                 lifecycle (registerOk>0 AND active>0) OR carried a client/lib UA.
//   unclassified  the DEFAULT SINK — any outside IP we can't positively call an agent
//                 (discovery-only with a browser/bot/other/none UA). This is the honest
//                 "I don't know what this is" count. Prompted by deckhand on Moltbook
//                 (2026-07-29): a binary fleet/not-fleet filter silently routes every
//                 un-enumerated thing (a new fleet egress, a NAT rebind, a plain-lib
//                 agent) into whichever side is the default, and you only find out which
//                 by whether it was loud. A third bucket makes not-having-classified-it
//                 visible instead of silent — but see the CANARY caveat printed on the
//                 report: a zero unclassified is only trustworthy once you've seen it
//                 fire at least once (a counter that never fired and one that CANNOT
//                 fire read identically). Injecting a synthetic unclassifiable probe on
//                 a schedule is the open item; not yet wired (needs a non-fleet source).

import fs from 'node:fs';
import path from 'node:path';

const args = process.argv.slice(2);
const fleetIps = new Set();
const fleetIpPrefixes = [];
const files = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--fleet-ip') fleetIps.add(args[++i]);
  else if (args[i] === '--fleet-ip-prefix') fleetIpPrefixes.push(args[++i]);
  else files.push(args[i]);
}

// Fleet identity from config, so the default invocation is the honest one.
// Flags still win by being additive — nothing here overrides an explicit --fleet-ip.
const splitList = (s) => (s ?? '').split(',').map((x) => x.trim()).filter(Boolean);
for (const ip of splitList(process.env.TELEGRAPH_FLEET_IP)) fleetIps.add(ip);
for (const p of splitList(process.env.TELEGRAPH_FLEET_IP_PREFIX)) fleetIpPrefixes.push(p);
const fleetConfigPath = path.join(import.meta.dirname, 'funnel-fleet.local.json');
if (fs.existsSync(fleetConfigPath)) {
  try {
    const cfg = JSON.parse(fs.readFileSync(fleetConfigPath, 'utf8'));
    for (const ip of cfg.ips ?? []) fleetIps.add(ip);
    for (const p of cfg.prefixes ?? []) fleetIpPrefixes.push(p);
  } catch (err) {
    // Loud, not silent: a broken config is indistinguishable from "no fleet" downstream,
    // and "no fleet" is exactly the state that inflates the external numbers.
    console.error(`funnel-report: could not read ${fleetConfigPath}: ${err.message}`);
    process.exit(1);
  }
}
// Loopback alone is not fleet identity — the relay's own outbound egress never
// looks like loopback, so a run with nothing configured cannot separate us from them.
const fleetConfigured = fleetIps.size > 0 || fleetIpPrefixes.length > 0;
if (files.length === 0) {
  const root = path.join(import.meta.dirname, '..');
  for (const f of ['relay-access-archive.log', 'relay-live.log']) {
    const p = path.join(root, f);
    if (fs.existsSync(p)) files.push(p);
  }
}

// Newer lines (commit adding uaClass) carry a trailing ` ua=<class>` token.
// The token is optional so this still parses lines logged before it landed.
const LINE = /^\[telegraph\] (\S+) (\S+) (\S+) (\d{3}) \d+ms(?: ua=(\S+))?$/;
// Log lines written before 2026-07-27 (commit 73b4767) carried no client IP.
// All traffic before then was fleet/local in practice; bucket it as such.
const OLD_LINE = /^\[telegraph\] (GET|POST|PUT|DELETE|HEAD|OPTIONS) (\S+) (\d{3}) \d+ms$/;
const isLoopback = (ip) => ip === '127.0.0.1' || ip === '::1' || ip.startsWith('::ffff:127.');
const isOurs = (ip) => isLoopback(ip) || fleetIps.has(ip) || fleetIpPrefixes.some((p) => ip.startsWith(p));

const stage = (method, p) => {
  if (method === 'GET' && (p === '/' || p === '/onboard' || p === '/v1/onboard'
    || p.startsWith('/docs') || p.startsWith('/README') || p === '/directory'
    || p === '/v1/directory')) return 'discovery';
  if (method === 'POST' && p === '/v1/register') return 'register';
  if ((method === 'POST' && p === '/v1/messages') || (method === 'GET' && p === '/v1/inbox')) return 'active';
  return null;
};

const perIp = new Map(); // ip -> {discovery, registerOk, registerFail, active, total, ua:{class->count}}
const uaDiscovery = new Map(); // ua class -> outside discovery hits (the reach-vs-bot signal)
let parsed = 0, skipped = 0, uaTagged = 0;
for (const file of files) {
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    let m = LINE.exec(line);
    let ip, method, pathName, status, ua;
    if (m) [, ip, method, pathName, status, ua] = m;
    else if ((m = OLD_LINE.exec(line))) { ip = '::1'; [, method, pathName, status] = m; }
    else { if (line.trim()) skipped++; continue; }
    parsed++;
    if (ua) uaTagged++;
    let rec = perIp.get(ip);
    if (!rec) perIp.set(ip, rec = { discovery: 0, registerOk: 0, registerFail: 0, active: 0, total: 0, ua: {} });
    rec.total++;
    if (ua) rec.ua[ua] = (rec.ua[ua] || 0) + 1;
    const s = stage(method, pathName);
    if (s === 'discovery') rec.discovery++;
    else if (s === 'register') (status[0] === '2' ? rec.registerOk++ : rec.registerFail++);
    else if (s === 'active') rec.active++;
    // Track discovery-by-UA-class for OUTSIDE traffic only (fleet excluded below,
    // but discovery reach is what we bucket — crawler vs real client vs browser).
    if (s === 'discovery' && ua && !isOurs(ip)) uaDiscovery.set(ua, (uaDiscovery.get(ua) || 0) + 1);
  }
}
// Dominant UA class per IP, for the per-row annotation.
const topUa = (rec) => {
  const e = Object.entries(rec.ua || {});
  if (!e.length) return null;
  return e.sort((a, b) => b[1] - a[1])[0][0];
};

// Positive "external agent" predicate: an outside IP earns the external bucket only on
// a PROTOCOL-level positive signal — it successfully registered (needs a valid keypair +
// signature, which a crawler can't fake) or it used the wire (register/active). A
// client/lib UA is NOT enough on its own: a scanner can send any UA string, so promoting
// on a single lib-ish hit among hundreds of browser hits over-counts (deckhand's
// "external predicate that quietly matches more than it should" — observed live 2026-07-29
// when two ~690-request crawlers landed in external off one stray lib UA). UA class stays
// a SEPARATE reach signal (the by-class breakdown below), decoupled from conversion.
const isExternalAgent = (rec) => rec.registerOk > 0 || rec.active > 0;

const ours = [...perIp].filter(([ip]) => isOurs(ip));
const outsideAll = [...perIp].filter(([ip]) => !isOurs(ip));
const external = outsideAll.filter(([, r]) => isExternalAgent(r));
const unclassified = outsideAll.filter(([, r]) => !isExternalAgent(r));
const sum = (rows, k) => rows.reduce((a, [, r]) => a + r[k], 0);

const printRows = (rows) => {
  for (const [ip, r] of rows.sort((a, b) => b[1].total - a[1].total)) {
    const ua = topUa(r);
    console.log(`  ${ip}  total=${r.total} discovery=${r.discovery} register(ok/fail)=${r.registerOk}/${r.registerFail} active=${r.active}${ua ? ` ua=${ua}` : ''}`);
  }
};
const printTotals = (label, rows) => console.log(`  ${label}: discovery=${sum(rows, 'discovery')} registerOk=${sum(rows, 'registerOk')} registerFail=${sum(rows, 'registerFail')} active=${sum(rows, 'active')}`);

console.log(`parsed ${parsed} log lines from ${files.length} file(s) (${skipped} non-access lines skipped; ${uaTagged} carry a UA class)`);
console.log(`fleet/local IPs: ${ours.length} — external-agent IPs: ${external.length} — unclassified IPs: ${unclassified.length}\n`);

if (!fleetConfigured) {
  console.log('!! FLEET UNCONFIGURED — the numbers below are NOT trustworthy.');
  console.log('!! No --fleet-ip/--fleet-ip-prefix, no TELEGRAPH_FLEET_IP[_PREFIX], no funnel-fleet.local.json.');
  console.log('!! Every request this box made to its own relay is being counted as an outside visitor,');
  console.log('!! and IPv6 privacy extensions rotate our egress address, so we appear as MANY visitors.');
  console.log('!! Measured 2026-08-12: unconfigured read 16 external IPs / 52 discovery / 3 registerOk;');
  console.log('!! the truth was 4 / 3 / 1. Configure fleet identity, then re-read.\n');
}

console.log('EXTERNAL AGENTS (positive protocol signal: registered ok, or used the wire):');
if (external.length === 0) {
  console.log('  none — no outside IP has positively identified as a Telegraph agent yet.');
} else {
  printRows(external);
  printTotals('TOTALS', external);
  console.log('  Reading: discovery>0 with registerOk=0 means an identified agent ARRIVED but bailed (friction).');
}

console.log('\nUNCLASSIFIED (default sink — outside IPs we can\'t positively call agents):');
if (unclassified.length === 0) {
  console.log('  0 — but a zero here is only trustworthy once this bucket has fired at least once.');
  console.log('  CANARY (open item): no synthetic unclassifiable probe is injected yet, so an empty');
  console.log('  bucket and a bucket that CANNOT fire (too-broad external predicate) read identically.');
} else {
  printRows(unclassified);
  printTotals('TOTALS', unclassified);
  console.log('  Reading: unclassified > 0 is not a metric, it\'s a PROMPT to go trace before trusting');
  console.log('  the external numbers — a new fleet egress, a NAT rebind, or a plain-lib agent lands here.');
}

// Reach-vs-bot: the honest agent-reach number across ALL outside discovery. Crawlers
// (bot) and browsers are not agents evaluating the API; client/lib UAs are the real
// agent-shaped reach. This spans both external and unclassified rows on purpose —
// it's the reach signal, orthogonal to the per-IP classification above.
if (uaDiscovery.size) {
  const order = ['client', 'lib', 'browser', 'bot', 'other', 'none'];
  const rows = [...uaDiscovery].sort((a, b) => (order.indexOf(a[0]) - order.indexOf(b[0])) || b[1] - a[1]);
  console.log('\nOUTSIDE discovery by UA class (client/lib = real agent reach; bot/browser = not):');
  for (const [cls, n] of rows) console.log(`  ${cls.padEnd(8)} ${n}`);
  const agentish = (uaDiscovery.get('client') || 0) + (uaDiscovery.get('lib') || 0);
  console.log(`  → agent-shaped discovery (client+lib): ${agentish}`);
} else {
  console.log('\n(no UA-tagged outside discovery yet — restart the relay so new lines carry ua=; older lines have no UA.)');
}
console.log(`\nFleet/local (context only): discovery=${sum(ours, 'discovery')} registerOk=${sum(ours, 'registerOk')} registerFail=${sum(ours, 'registerFail')} active=${sum(ours, 'active')}`);
