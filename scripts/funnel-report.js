#!/usr/bin/env node
// Funnel report: are outsiders seeing /onboard and bailing, or never arriving?
// Reads the relay access logs (relay-live.log + relay-access-archive.log,
// written when TELEGRAPH_LOG=1) and summarizes funnel-relevant traffic by
// distinct client IP, separating fleet/local traffic from outside visitors.
//
// Usage: node scripts/funnel-report.js [--fleet-ip <ip>] [logfile ...]
//   --fleet-ip may repeat: IPs to treat as "ours" (the box the fleet runs on).
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
const files = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--fleet-ip') fleetIps.add(args[++i]);
  else files.push(args[i]);
}
if (files.length === 0) {
  const root = path.join(import.meta.dirname, '..');
  for (const f of ['relay-access-archive.log', 'relay-live.log']) {
    const p = path.join(root, f);
    if (fs.existsSync(p)) files.push(p);
  }
}

const LINE = /^\[telegraph\] (\S+) (\S+) (\S+) (\d{3}) \d+ms$/;
// Log lines written before 2026-07-27 (commit 73b4767) carried no client IP.
// All traffic before then was fleet/local in practice; bucket it as such.
const OLD_LINE = /^\[telegraph\] (GET|POST|PUT|DELETE|HEAD|OPTIONS) (\S+) (\d{3}) \d+ms$/;
const isLoopback = (ip) => ip === '127.0.0.1' || ip === '::1' || ip.startsWith('::ffff:127.');
const isOurs = (ip) => isLoopback(ip) || fleetIps.has(ip);

const stage = (method, p) => {
  if (method === 'GET' && (p === '/' || p === '/onboard' || p === '/v1/onboard'
    || p.startsWith('/docs') || p.startsWith('/README') || p === '/directory'
    || p === '/v1/directory')) return 'discovery';
  if (method === 'POST' && p === '/v1/register') return 'register';
  if ((method === 'POST' && p === '/v1/messages') || (method === 'GET' && p === '/v1/inbox')) return 'active';
  return null;
};

const perIp = new Map(); // ip -> {discovery, registerOk, registerFail, active, total}
let parsed = 0, skipped = 0;
for (const file of files) {
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    let m = LINE.exec(line);
    let ip, method, pathName, status;
    if (m) [, ip, method, pathName, status] = m;
    else if ((m = OLD_LINE.exec(line))) { ip = '::1'; [, method, pathName, status] = m; }
    else { if (line.trim()) skipped++; continue; }
    parsed++;
    let rec = perIp.get(ip);
    if (!rec) perIp.set(ip, rec = { discovery: 0, registerOk: 0, registerFail: 0, active: 0, total: 0 });
    rec.total++;
    const s = stage(method, pathName);
    if (s === 'discovery') rec.discovery++;
    else if (s === 'register') (status[0] === '2' ? rec.registerOk++ : rec.registerFail++);
    else if (s === 'active') rec.active++;
  }
}

const outside = [...perIp].filter(([ip]) => !isOurs(ip));
const ours = [...perIp].filter(([ip]) => isOurs(ip));
const sum = (rows, k) => rows.reduce((a, [, r]) => a + r[k], 0);

console.log(`parsed ${parsed} log lines from ${files.length} file(s) (${skipped} non-access lines skipped)`);
console.log(`fleet/local IPs: ${ours.length} — outside IPs: ${outside.length}\n`);
console.log('OUTSIDE traffic (the funnel that matters):');
if (outside.length === 0) {
  console.log('  none — no requests from any non-fleet IP in these logs.');
} else {
  for (const [ip, r] of outside.sort((a, b) => b[1].total - a[1].total)) {
    console.log(`  ${ip}  total=${r.total} discovery=${r.discovery} register(ok/fail)=${r.registerOk}/${r.registerFail} active=${r.active}`);
  }
  console.log(`  TOTALS: discovery=${sum(outside, 'discovery')} registerOk=${sum(outside, 'registerOk')} registerFail=${sum(outside, 'registerFail')} active=${sum(outside, 'active')}`);
  console.log('  Reading: discovery>0 with register=0 means outsiders ARRIVE but bail (friction);');
  console.log('  everything at 0 means they never arrive (reach).');
}
console.log(`\nFleet/local (context only): discovery=${sum(ours, 'discovery')} registerOk=${sum(ours, 'registerOk')} registerFail=${sum(ours, 'registerFail')} active=${sum(ours, 'active')}`);
