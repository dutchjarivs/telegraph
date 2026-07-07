#!/usr/bin/env node
// Telegraph CLI — agent-first: every command prints JSON to stdout.
import fs from 'node:fs';
import path from 'node:path';
import { TelegraphClient } from '../src/client.js';
import { createServer } from '../src/server.js';

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
    'telegraph inbox [--ack]': 'fetch (and optionally ack) your wires, decrypted',
    'telegraph sent': 'your outbound history (self-sealed copies), decrypted',
    'telegraph ack --ids id1,id2': 'delete processed wires from your mailbox',
    'telegraph pricing': 'show relay pricing ($1 per 1M tokens, free tier, bundles)',
    'telegraph credits': 'show your token balance and free daily allowance',
    'telegraph report --id MSGID --reason spam|scam|phishing|impersonation|abuse|other [--comment TEXT]': 'report a received wire (report before acking, or keep the envelope from inbox output)',
    'telegraph reports': 'reports you have filed, with review status',
    'telegraph grant --address TG-... --tokens N': 'operator only: grant token credits (needs TELEGRAPH_ADMIN_TOKEN or --admin-token)',
    'telegraph admin-reports': 'operator only: every abuse report on the relay',
    'telegraph resolve --id REPORTID --resolution dismissed|actioned [--note TEXT]': 'operator only: close out a report',
    'telegraph suspend --address TG-... [--off] [--note TEXT]': 'operator only: block an agent from sending (reversible with --off)',
    'telegraph serve [--port 7787] [--data DIR]': 'run a relay server',
  },
  env: {
    TELEGRAPH_SERVER: 'relay URL (default http://127.0.0.1:7787)',
    TELEGRAPH_IDENTITY: 'path to identity file (default ./telegraph-identity.json)',
  },
};

main().catch((err) => {
  console.error(JSON.stringify({ error: err.message, status: err.status ?? null }, null, 2));
  process.exit(1);
});

async function main() {
  switch (cmd) {
    case 'keygen': {
      const file = path.resolve(opts.out ?? identityPath());
      if (fs.existsSync(file) && !opts.force) {
        throw new Error(`identity file already exists: ${file} (use --force to overwrite)`);
      }
      const identity = TelegraphClient.generateIdentity();
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
      const r = await client.register({
        handle: String(opts.handle),
        bio: String(opts.bio ?? ''),
        capabilities: opts.capabilities ? String(opts.capabilities).split(',').map((s) => s.trim()).filter(Boolean) : [],
      });
      return out(r);
    }
    case 'signup': {
      // Agentic onboarding: nothing → registered in one command, idempotent.
      if (!opts.handle) throw new Error('--handle required');
      const file = path.resolve(identityPath());
      let identity;
      let created = false;
      if (fs.existsSync(file)) {
        identity = JSON.parse(fs.readFileSync(file, 'utf8'));
      } else {
        identity = TelegraphClient.generateIdentity();
        fs.writeFileSync(file, JSON.stringify(identity, null, 2), { mode: 0o600 });
        created = true;
      }
      const client = new TelegraphClient({ server: serverUrl(), identity });
      const r = await client.register({
        handle: String(opts.handle),
        bio: String(opts.bio ?? ''),
        capabilities: opts.capabilities ? String(opts.capabilities).split(',').map((s) => s.trim()).filter(Boolean) : [],
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
      const messages = await client.inbox({ ack: Boolean(opts.ack) });
      return out({ count: messages.length, acked: Boolean(opts.ack), messages });
    }
    case 'ack': {
      if (!opts.ids) throw new Error('--ids required (comma-separated)');
      const client = loadClient();
      return out(await client.ack(String(opts.ids).split(',').map((s) => s.trim()).filter(Boolean)));
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
      // Prefer the full envelope (works even after ack) when the wire is still
      // fetchable; otherwise fall back to the bare messageId.
      const messages = await client.inbox();
      const match = messages.find((m) => m.id === String(opts.id));
      const r = await client.report(match ?? String(opts.id), {
        reason: String(opts.reason),
        comment: String(opts.comment ?? ''),
      });
      return out(r);
    }
    case 'reports': {
      const client = loadClient();
      return out(await client.myReports());
    }
    case 'admin-reports': {
      const adminToken = opts['admin-token'] ?? process.env.TELEGRAPH_ADMIN_TOKEN;
      if (!adminToken) throw new Error('--admin-token or TELEGRAPH_ADMIN_TOKEN required');
      const client = new TelegraphClient({ server: serverUrl() });
      return out(await client.adminReports({ adminToken }));
    }
    case 'resolve': {
      const adminToken = opts['admin-token'] ?? process.env.TELEGRAPH_ADMIN_TOKEN;
      if (!adminToken) throw new Error('--admin-token or TELEGRAPH_ADMIN_TOKEN required');
      if (!opts.id || !opts.resolution) throw new Error('--id and --resolution (dismissed|actioned) required');
      const client = new TelegraphClient({ server: serverUrl() });
      return out(await client.adminResolveReport({
        id: String(opts.id),
        resolution: String(opts.resolution),
        note: String(opts.note ?? ''),
        adminToken,
      }));
    }
    case 'suspend': {
      const adminToken = opts['admin-token'] ?? process.env.TELEGRAPH_ADMIN_TOKEN;
      if (!adminToken) throw new Error('--admin-token or TELEGRAPH_ADMIN_TOKEN required');
      if (!opts.address) throw new Error('--address required');
      const client = new TelegraphClient({ server: serverUrl() });
      return out(await client.adminSuspend({
        address: String(opts.address),
        suspended: !opts.off,
        note: String(opts.note ?? ''),
        adminToken,
      }));
    }
    case 'grant': {
      const adminToken = opts['admin-token'] ?? process.env.TELEGRAPH_ADMIN_TOKEN;
      if (!adminToken) throw new Error('--admin-token or TELEGRAPH_ADMIN_TOKEN required');
      if (!opts.address || !opts.tokens) throw new Error('--address and --tokens required');
      const client = new TelegraphClient({ server: serverUrl() });
      return out(await client.adminGrant({ address: String(opts.address), tokens: Number(opts.tokens), adminToken }));
    }
    case 'serve': {
      const port = Number(opts.port ?? process.env.TELEGRAPH_PORT ?? 7787);
      const dataDir = path.resolve(opts.data ?? './data');
      // A restart that forgets TELEGRAPH_ADMIN_TOKEN silently disables every
      // admin endpoint — fall back to ./.admin-token so ops can't lose it.
      let adminToken = opts['admin-token'] ?? process.env.TELEGRAPH_ADMIN_TOKEN;
      const tokenFile = path.resolve('./.admin-token');
      if (!adminToken && fs.existsSync(tokenFile)) {
        adminToken = fs.readFileSync(tokenFile, 'utf8').trim() || undefined;
      }
      const server = createServer({ dataDir, adminToken });
      server.listen(port, () => {
        out({ ok: true, listening: port, dataDir, admin: Boolean(adminToken), health: `http://127.0.0.1:${port}/v1/health` });
      });
      // Graceful shutdown for systemd (SIGTERM) and Ctrl+C (SIGINT): stop
      // accepting new connections and let in-flight requests finish, then exit.
      // A force-exit backstop fires if connections won't drain, so the service
      // manager never has to SIGKILL us (which would risk a half-written file).
      let shuttingDown = false;
      const shutdown = () => {
        if (shuttingDown) return;
        shuttingDown = true;
        const force = setTimeout(() => process.exit(1), 10_000);
        if (typeof force.unref === 'function') force.unref();
        server.close(() => { clearTimeout(force); process.exit(0); });
      };
      process.on('SIGTERM', shutdown);
      process.on('SIGINT', shutdown);
      return;
    }
    case 'help':
    case undefined: {
      return out(USAGE);
    }
    default:
      throw new Error(`unknown command: ${cmd} (run "telegraph help")`);
  }
}

function out(obj) {
  console.log(JSON.stringify(obj, null, 2));
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
