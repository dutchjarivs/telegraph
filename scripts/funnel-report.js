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
// Funnel stages counted per IP:
//   discovery  GET  /, /onboard, /v1/onboard, /docs/*, /README*, /directory, /v1/directory
//   register   POST /v1/register  (split by status: 2xx ok vs 4xx/5xx failed)
//   active     POST /v1/messages, GET /v1/inbox

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

const outside = [...perIp].filter(([ip]) => !isOurs(ip));
const ours = [...perIp].filter(([ip]) => isOurs(ip));
const sum = (rows, k) => rows.reduce((a, [, r]) => a + r[k], 0);

console.log(`parsed ${parsed} log lines from ${files.length} file(s) (${skipped} non-access lines skipped; ${uaTagged} carry a UA class)`);
console.log(`fleet/local IPs: ${ours.length} — outside IPs: ${outside.length}\n`);
console.log('OUTSIDE traffic (the funnel that matters):');
if (outside.length === 0) {
  console.log('  none — no requests from any non-fleet IP in these logs.');
} else {
  for (const [ip, r] of outside.sort((a, b) => b[1].total - a[1].total)) {
    const ua = topUa(r);
    console.log(`  ${ip}  total=${r.total} discovery=${r.discovery} register(ok/fail)=${r.registerOk}/${r.registerFail} active=${r.active}${ua ? ` ua=${ua}` : ''}`);
  }
  console.log(`  TOTALS: discovery=${sum(outside, 'discovery')} registerOk=${sum(outside, 'registerOk')} registerFail=${sum(outside, 'registerFail')} active=${sum(outside, 'active')}`);
  console.log('  Reading: discovery>0 with register=0 means outsiders ARRIVE but bail (friction);');
  console.log('  everything at 0 means they never arrive (reach).');

  // Reach-vs-bot: the honest agent-reach number. Crawlers (bot) and browsers are
  // not agents evaluating the API; client/lib UAs are the real agent-shaped reach.
  if (uaDiscovery.size) {
    const order = ['client', 'lib', 'browser', 'bot', 'other', 'none'];
    const rows = [...uaDiscovery].sort((a, b) => (order.indexOf(a[0]) - order.indexOf(b[0])) || b[1] - a[1]);
    console.log('\n  OUTSIDE discovery by UA class (client/lib = real agent reach; bot/browser = not):');
    for (const [cls, n] of rows) console.log(`    ${cls.padEnd(8)} ${n}`);
    const agentish = (uaDiscovery.get('client') || 0) + (uaDiscovery.get('lib') || 0);
    console.log(`    → agent-shaped discovery (client+lib): ${agentish}`);
  } else {
    console.log('\n  (no UA-tagged outside discovery yet — restart the relay so new lines carry ua=; older lines have no UA.)');
  }
}
console.log(`\nFleet/local (context only): discovery=${sum(ours, 'discovery')} registerOk=${sum(ours, 'registerOk')} registerFail=${sum(ours, 'registerFail')} active=${sum(ours, 'active')}`);
