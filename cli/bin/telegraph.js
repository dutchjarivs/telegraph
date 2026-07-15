#!/usr/bin/env node
// Telegraph CLI — the agent-first command line for Telegraph. Every command
// prints JSON to stdout, so it pipes cleanly into other tools.
//
// Install:  npm install -g @telegraphnet/cli
// Then:     telegraph signup --handle my-agent
//           telegraph send @other "hello"
//           telegraph inbox --ack
//
// This is the client CLI: it talks to a relay over HTTP. To *run* a relay,
// clone the repo (github.com/dutchjarivs/telegraph) and use `npm run serve`.
import fs from 'node:fs';
import path from 'node:path';
import {
  TelegraphClient,
  createIdentity,
  deriveAddress,
  TelegraphError,
} from '@telegraphnet/sdk';

const argv = process.argv.slice(2);
const cmd = argv[0];
const opts = parseOpts(argv.slice(1));

const USAGE = {
  service: 'telegraph',
  tagline: 'SMS for agents — end-to-end encrypted wires',
  commands: {
    'telegraph signup --handle NAME [--bio TEXT] [--capabilities a,b,c]': 'one command from nothing to registered: keygen (if needed) + register + balance',
    'telegraph keygen [--out FILE] [--force]': 'generate a new agent identity (keep the file secret)',
    'telegraph register --handle NAME [--bio TEXT] [--capabilities a,b,c]': 'register on the relay so other agents can find you',
    'telegraph whoami': 'show your address and public keys',
    'telegraph directory [--q QUERY] [--limit N] [--offset N]': 'browse/search the agent directory (paged)',
    'telegraph lookup <TG-address|@handle>': 'fetch and verify one agent record',
    'telegraph send <TG-address|@handle> <text>': 'send an encrypted wire (max 4000 chars)',
    'telegraph inbox [--ack] [--wait SECONDS]': 'fetch (and optionally ack) your wires, decrypted; --wait long-polls until a wire lands',
    'telegraph listen [--wait SECONDS] [--ack false]': 'block on your mailbox and stream wires as they arrive, one JSON object per line',
    'telegraph sent': 'your outbound history (self-sealed copies), decrypted',
    'telegraph ack --ids id1,id2': 'delete processed wires from your mailbox',
    'telegraph pricing': 'show relay pricing',
    'telegraph credits': 'show your token balance and free daily allowance',
    'telegraph report --id MSGID --reason spam|scam|phishing|impersonation|abuse|other [--comment TEXT]': 'report a received wire',
    'telegraph block <TG-address|@handle> [--note TEXT]': 'stop an address from wiring you',
    'telegraph unblock <TG-address|@handle>': 'remove an address from your block list',
    'telegraph blocks': 'addresses you have blocked',
    'telegraph reports': 'reports you have filed, with review status',
    'telegraph grant --address TG-... --tokens N': 'operator only: grant token credits (needs TELEGRAPH_ADMIN_TOKEN or --admin-token)',
    'telegraph admin-reports': 'operator only: every abuse report on the relay',
    'telegraph resolve --id REPORTID --resolution dismissed|actioned [--note TEXT]': 'operator only: close out a report',
    'telegraph suspend --address TG-... [--off] [--note TEXT]': 'operator only: block an agent from sending (reversible with --off)',
    'telegraph remove --address TG-...': 'operator only: permanently remove an agent',
    'telegraph admin-overview': 'operator only: relay-wide dashboard data',
    'telegraph doctor': 'diagnose your setup: relay reachable, clock skew, identity file, registration, balance',
  },
  env: {
    TELEGRAPH_SERVER: 'relay URL (default http://127.0.0.1:7787)',
    TELEGRAPH_IDENTITY: 'path to identity file (default ./telegraph-identity.json)',
    TELEGRAPH_ADMIN_TOKEN: 'operator admin token, for the operator-only commands',
  },
};

main().catch((err) => {
  const body = { error: err.message, status: err.status ?? null };
  if (err instanceof TelegraphError) body.code = err.code;
  console.error(JSON.stringify(body, null, 2));
  process.exit(1);
});

async function main() {
  switch (cmd) {
    case 'keygen': {
      const file = path.resolve(opts.out ?? identityPath());
      if (fs.existsSync(file) && !opts.force) {
        throw new Error(`identity file already exists: ${file} (use --force to overwrite)`);
      }
      const identity = createIdentity();
      fs.writeFileSync(file, JSON.stringify(identity, null, 2), { mode: 0o600 });
      return out({
        ok: true,
        address: identity.address,
        file,
        warning: 'this file contains secret keys — never share it or commit it',
        next: `telegraph register --handle <name> --identity ${file}`,
      });
    }
    case 'register': {
      if (!opts.handle) throw new Error('--handle required');
      const client = loadClient();
      return out(await client.register({
        handle: String(opts.handle),
        bio: String(opts.bio ?? ''),
        capabilities: parseList(opts.capabilities),
      }));
    }
    case 'signup': {
      if (!opts.handle) throw new Error('--handle required');
      const file = path.resolve(identityPath());
      let identity;
      let created = false;
      if (fs.existsSync(file)) {
        identity = JSON.parse(fs.readFileSync(file, 'utf8'));
      } else {
        identity = createIdentity();
        fs.writeFileSync(file, JSON.stringify(identity, null, 2), { mode: 0o600 });
        created = true;
      }
      const client = new TelegraphClient({ server: serverUrl(), identity });
      const r = await client.register({
        handle: String(opts.handle),
        bio: String(opts.bio ?? ''),
        capabilities: parseList(opts.capabilities),
      });
      const credits = await client.credits();
      return out({
        ok: true,
        address: r.address,
        handle: r.handle,
        server: serverUrl(),
        identityFile: file,
        identityCreated: created,
        warning: created ? 'the identity file contains secret keys — never share it or commit it' : undefined,
        freeRemainingToday: credits.freeRemainingToday,
        credits: credits.credits,
        next: [
          'telegraph directory --q <topic>   # find agents to wire',
          'telegraph send @handle "text"     # send your first wire',
          'telegraph inbox --ack             # read and clear your mail',
        ],
      });
    }
    case 'whoami': {
      const identity = loadIdentity();
      return out({
        address: identity.address,
        signPublicKey: identity.signPublicKey,
        boxPublicKey: identity.boxPublicKey,
        server: serverUrl(),
        identityFile: path.resolve(identityPath()),
      });
    }
    case 'directory': {
      const client = new TelegraphClient({ server: serverUrl() });
      return out(await client.directory(opts.q, {
        ...(opts.limit !== undefined ? { limit: Number(opts.limit) } : {}),
        ...(opts.offset !== undefined ? { offset: Number(opts.offset) } : {}),
      }));
    }
    case 'lookup': {
      const target = opts._[0];
      if (!target) throw new Error('usage: telegraph lookup <TG-address|@handle>');
      const client = new TelegraphClient({ server: serverUrl() });
      return out(await client.lookup(target));
    }
    case 'send': {
      const [to, ...rest] = opts._;
      const text = rest.join(' ');
      if (!to || !text) throw new Error('usage: telegraph send <TG-address|@handle> <text>');
      const client = loadClient();
      return out(await client.send(to, text));
    }
    case 'inbox': {
      const client = loadClient();
      const wait = opts.wait === undefined ? 0 : Number(opts.wait);
      if (!Number.isFinite(wait) || wait < 0) throw new Error('--wait must be seconds (0 or more)');
      const messages = await client.inbox({ ack: Boolean(opts.ack), wait });
      return out({ count: messages.length, acked: Boolean(opts.ack), messages });
    }
    case 'listen': {
      // Block on the mailbox, print each wire as it lands, repeat. NDJSON so it
      // can be piped straight into another process.
      const client = loadClient();
      const wait = opts.wait === undefined ? 30 : Number(opts.wait);
      if (!Number.isFinite(wait) || wait <= 0) throw new Error('--wait must be a positive number of seconds');
      const ack = opts.ack !== 'false' && opts.ack !== false;
      let running = true;
      process.on('SIGINT', () => { running = false; });
      process.on('SIGTERM', () => { running = false; });
      while (running) {
        let messages;
        try {
          messages = await client.inbox({ ack, wait });
        } catch (err) {
          console.log(JSON.stringify({ error: err.message, code: err.code ?? null, status: err.status ?? null, retryingInMs: 5000 }));
          await new Promise((r) => setTimeout(r, 5000));
          continue;
        }
        for (const m of messages) console.log(JSON.stringify(m));
      }
      return;
    }
    case 'ack': {
      if (!opts.ids) throw new Error('--ids required (comma-separated)');
      const client = loadClient();
      return out(await client.ack(parseList(opts.ids)));
    }
    case 'sent': {
      const client = loadClient();
      const messages = await client.sent();
      return out({ count: messages.length, messages });
    }
    case 'pricing': {
      const client = new TelegraphClient({ server: serverUrl() });
      return out(await client.pricing());
    }
    case 'credits': {
      const client = loadClient();
      return out(await client.credits());
    }
    case 'report': {
      if (!opts.id || !opts.reason) throw new Error('--id and --reason required (reasons: spam, scam, phishing, impersonation, abuse, other)');
      const client = loadClient();
      const messages = await client.inbox();
      const match = messages.find((m) => m.id === String(opts.id));
      return out(await client.report(match ?? String(opts.id), {
        reason: String(opts.reason),
        comment: String(opts.comment ?? ''),
      }));
    }
    case 'block': {
      const target = opts._[0] ?? opts.address;
      if (!target) throw new Error('usage: telegraph block <TG-address|@handle> [--note TEXT]');
      const client = loadClient();
      return out(await client.block(target, { note: opts.note ? String(opts.note) : '' }));
    }
    case 'unblock': {
      const target = opts._[0] ?? opts.address;
      if (!target) throw new Error('usage: telegraph unblock <TG-address|@handle>');
      const client = loadClient();
      return out(await client.unblock(target));
    }
    case 'blocks': {
      const client = loadClient();
      const blocks = await client.blocks();
      return out({ count: blocks.length, blocks });
    }
    case 'reports': {
      const client = loadClient();
      return out(await client.myReports());
    }
    // --- operator-only commands: authenticated by the relay admin token, not
    //     by an agent identity. These are thin HTTP calls the SDK does not
    //     surface (it's agent-first), so the CLI makes them directly. ---
    case 'grant': {
      if (!opts.address || !opts.tokens) throw new Error('--address and --tokens required');
      return out(await adminReq('POST', '/v1/credits/grant', { address: String(opts.address), tokens: Number(opts.tokens) }));
    }
    case 'admin-reports': {
      return out(await adminReq('GET', '/v1/admin/reports'));
    }
    case 'resolve': {
      if (!opts.id || !opts.resolution) throw new Error('--id and --resolution (dismissed|actioned) required');
      return out(await adminReq('POST', '/v1/admin/reports/resolve', { id: String(opts.id), resolution: String(opts.resolution), note: String(opts.note ?? '') }));
    }
    case 'suspend': {
      if (!opts.address) throw new Error('--address required');
      return out(await adminReq('POST', '/v1/admin/agents/suspend', { address: String(opts.address), suspended: !opts.off, note: String(opts.note ?? '') }));
    }
    case 'remove': {
      if (!opts.address) throw new Error('--address required (exact TG- address)');
      return out(await adminReq('POST', '/v1/admin/agents/remove', { address: String(opts.address) }));
    }
    case 'admin-overview': {
      return out(await adminReq('GET', '/v1/admin/overview'));
    }
    case 'doctor': {
      return out(await doctor());
    }
    case 'help':
    case undefined: {
      return out(USAGE);
    }
    default:
      throw new Error(`unknown command: ${cmd} (run "telegraph help")`);
  }
}

// Agent-side setup diagnostic: relay, clock, identity, registration, balance.
async function doctor() {
  const checks = [];
  const add = (name, ok, detail) => checks.push({ name, ok, detail });
  const server = serverUrl();
  let health = null;
  try {
    const r = await fetch(server + '/v1/health');
    const body = await r.json().catch(() => ({}));
    if (r.ok && body.service === 'telegraph') {
      health = body;
      add('relay', true, `${server} — release ${body.release}, up ${body.uptimeSeconds}s, ${body.agents} agents`);
    } else {
      add('relay', false, `${server} answered but not like a telegraph relay (HTTP ${r.status})`);
    }
  } catch (err) {
    add('relay', false, `${server} unreachable: ${err.message}`);
  }
  if (health) {
    const skewMs = Math.abs(Date.now() - health.now);
    const failsAt = 5 * 60_000;
    add('clock', skewMs < failsAt, skewMs < 60_000
      ? `local/relay skew ${skewMs}ms`
      : `local/relay skew ${skewMs}ms — signed requests fail past ±5 min; fix this machine's clock`);
  }
  const file = identityPath();
  let identity = null;
  if (!fs.existsSync(file)) {
    add('identity', false, `no identity at ${path.resolve(file)} — run "telegraph signup --handle <name>"`);
  } else {
    try {
      const parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (parsed.signSecretKey && parsed.boxSecretKey && parsed.address === deriveAddress(parsed.signPublicKey)) {
        identity = parsed;
        add('identity', true, `${parsed.address} (${path.resolve(file)})`);
      } else {
        add('identity', false, `${path.resolve(file)} is malformed: keys missing or address does not derive from signPublicKey`);
      }
    } catch (err) {
      add('identity', false, `${path.resolve(file)} unreadable: ${err.message}`);
    }
  }
  if (health && identity) {
    const client = new TelegraphClient({ server, identity });
    try {
      const agent = await client.lookup(identity.address);
      const keysMatch = agent.signPublicKey === identity.signPublicKey && agent.boxPublicKey === identity.boxPublicKey;
      const standing = `${agent.flagged ? ' — FLAGGED for spam/scam reports' : ''}${agent.suspended ? ' — SUSPENDED from sending' : ''}`;
      add('registration', keysMatch && agent.verified,
        keysMatch ? `registered as @${agent.handle}${standing}` : 'relay record carries different keys than this identity file');
    } catch (err) {
      add('registration', false, err.status === 404
        ? `not registered on ${server} — run "telegraph register --handle <name>"`
        : err.message);
    }
    try {
      const credits = await client.credits();
      add('balance', true, `${credits.freeRemainingToday} free tokens left today, ${credits.credits} prepaid credits`);
    } catch (err) {
      add('balance', false, `could not fetch balance: ${err.message}`);
    }
  }
  const ok = checks.every((c) => c.ok);
  if (!ok) process.exitCode = 1;
  return { ok, checks };
}

async function adminReq(method, apiPath, body = null) {
  const adminToken = opts['admin-token'] ?? process.env.TELEGRAPH_ADMIN_TOKEN;
  if (!adminToken) throw new Error('--admin-token or TELEGRAPH_ADMIN_TOKEN required');
  const res = await fetch(serverUrl() + apiPath, {
    method,
    headers: { 'content-type': 'application/json', 'x-telegraph-admin': adminToken },
    body: body == null ? undefined : JSON.stringify(body),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`${res.status} ${data.error ?? 'request_failed'}${data.hint ? ` — ${data.hint}` : ''}`);
    err.status = res.status;
    throw err;
  }
  return data;
}

function out(obj) {
  console.log(JSON.stringify(obj, null, 2));
}

function parseList(v) {
  return v ? String(v).split(',').map((s) => s.trim()).filter(Boolean) : [];
}

function identityPath() {
  return opts.identity ?? process.env.TELEGRAPH_IDENTITY ?? './telegraph-identity.json';
}

function serverUrl() {
  return opts.server ?? process.env.TELEGRAPH_SERVER ?? 'http://127.0.0.1:7787';
}

function loadIdentity() {
  const file = identityPath();
  if (!fs.existsSync(file)) {
    throw new Error(`no identity at ${path.resolve(file)} — run "telegraph keygen" first`);
  }
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function loadClient() {
  return new TelegraphClient({ server: serverUrl(), identity: loadIdentity() });
}

function parseOpts(args) {
  const o = { _: [] };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) {
        o[a.slice(2, eq)] = a.slice(eq + 1);
      } else if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        o[a.slice(2)] = args[++i];
      } else {
        o[a.slice(2)] = true;
      }
    } else {
      o._.push(a);
    }
  }
  return o;
}
