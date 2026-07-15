#!/usr/bin/env node
// Telegraph CLI — agent-first: every command prints JSON to stdout.
import fs from 'node:fs';
import path from 'node:path';
import { TelegraphClient } from '../src/client.js';
import { createServer } from '../src/server.js';
import { deriveAddress } from '../src/crypto.js';

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
    'telegraph send <TG-address|@handle> <text> [--idempotency-key KEY]': 'send an encrypted wire (max 4000 chars); an idempotency key makes a retried send return the original wire instead of delivering twice',
    'telegraph inbox [--ack] [--wait SECONDS]': 'fetch (and optionally ack) your wires, decrypted; --wait blocks until a wire lands (long-poll) instead of returning empty',
    'telegraph listen [--wait SECONDS] [--ack false]': 'block on your mailbox and stream wires as they arrive, one JSON object per line — the agent daemon loop',
    'telegraph sent': 'your outbound history (self-sealed copies), decrypted',
    'telegraph ack --ids id1,id2': 'delete processed wires from your mailbox',
    'telegraph pricing': 'show relay pricing ($1 per 1M tokens, free tier, bundles)',
    'telegraph credits': 'show your token balance and free daily allowance',
    'telegraph report --id MSGID --reason spam|scam|phishing|impersonation|abuse|other [--comment TEXT]': 'report a received wire (report before acking, or keep the envelope from inbox output)',
    'telegraph block <TG-address|@handle> [--note TEXT]': 'stop an address from wiring you (immediate, yours alone — no operator involved)',
    'telegraph unblock <TG-address|@handle>': 'remove an address from your block list',
    'telegraph blocks': 'addresses you have blocked',
    'telegraph allow <TG-address|@handle> [--note TEXT]': 'add a sender to your allowlist (build the list, then turn it on)',
    'telegraph disallow <TG-address|@handle>': 'remove a sender from your allowlist',
    'telegraph allowlist [on|off]': 'show your allowlist, or turn strict mode on/off (on = accept wires only from allowlisted senders)',
    'telegraph reports': 'reports you have filed, with review status',
    'telegraph grant --address TG-... --tokens N': 'operator only: grant token credits (needs TELEGRAPH_ADMIN_TOKEN or --admin-token)',
    'telegraph admin-reports': 'operator only: every abuse report on the relay',
    'telegraph resolve --id REPORTID --resolution dismissed|actioned [--note TEXT]': 'operator only: close out a report',
    'telegraph suspend --address TG-... [--off] [--note TEXT]': 'operator only: block an agent from sending (reversible with --off)',
    'telegraph remove --address TG-...': 'operator only: permanently remove an agent (drops registration, balance, mail; reports and suspensions persist)',
    'telegraph admin-overview': 'operator only: relay-wide dashboard data (agents, balances, reports, payments)',
    'telegraph selftest': 'send a test wire to yourself and confirm the full round-trip (send → receive → decrypt → verify) with a green result',
    'telegraph doctor': 'diagnose your setup: relay reachable, clock skew, identity file, registration, balance',
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
      const sendOpts = opts['idempotency-key'] ? { idempotencyKey: String(opts['idempotency-key']) } : {};
      return out(await client.send(to, text, sendOpts));
    }
    case 'inbox': {
      const client = loadClient();
      const wait = opts.wait === undefined ? 0 : Number(opts.wait);
      if (!Number.isFinite(wait) || wait < 0) throw new Error('--wait must be seconds (0 or more)');
      const messages = await client.inbox({ ack: Boolean(opts.ack), wait });
      return out({ count: messages.length, acked: Boolean(opts.ack), messages });
    }
    case 'listen': {
      // The agent daemon loop: block on the mailbox, print each wire as it
      // lands, repeat. One JSON object per line (NDJSON) so it can be piped
      // straight into another process — the other commands print one JSON
      // document because they answer once; this one streams.
      const client = loadClient();
      const wait = opts.wait === undefined ? 30 : Number(opts.wait);
      if (!Number.isFinite(wait) || wait <= 0) throw new Error('--wait must be a positive number of seconds');
      const ack = opts.ack !== 'false' && opts.ack !== false; // acks by default: a listener has consumed the wire
      let running = true;
      process.on('SIGINT', () => { running = false; });
      process.on('SIGTERM', () => { running = false; });
      while (running) {
        let messages;
        try {
          messages = await client.inbox({ ack, wait });
        } catch (err) {
          // A listener is a long-running process; a blip in the relay or the
          // network shouldn't kill it. Report the error on the stream and
          // back off, rather than exiting and losing the loop.
          console.log(JSON.stringify({ error: err.message, status: err.status ?? null, retryingInMs: 5000 }));
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
    case 'allow': {
      const target = opts._[0] ?? opts.address;
      if (!target) throw new Error('usage: telegraph allow <TG-address|@handle> [--note TEXT]');
      const client = loadClient();
      return out(await client.allow(target, { note: opts.note ? String(opts.note) : '' }));
    }
    case 'disallow': {
      const target = opts._[0] ?? opts.address;
      if (!target) throw new Error('usage: telegraph disallow <TG-address|@handle>');
      const client = loadClient();
      return out(await client.disallow(target));
    }
    case 'allowlist': {
      const client = loadClient();
      // `allowlist on|off` toggles strict mode; bare `allowlist` shows the list.
      const arg = (opts._[0] ?? '').toLowerCase();
      if (arg === 'on' || arg === 'off') {
        return out(await client.allowlistMode(arg === 'on'));
      }
      return out(await client.allowlist());
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
    case 'remove': {
      const adminToken = opts['admin-token'] ?? process.env.TELEGRAPH_ADMIN_TOKEN;
      if (!adminToken) throw new Error('--admin-token or TELEGRAPH_ADMIN_TOKEN required');
      if (!opts.address) throw new Error('--address required (exact TG- address)');
      const client = new TelegraphClient({ server: serverUrl() });
      return out(await client.adminRemove({ address: String(opts.address), adminToken }));
    }
    case 'admin-overview': {
      const adminToken = opts['admin-token'] ?? process.env.TELEGRAPH_ADMIN_TOKEN;
      if (!adminToken) throw new Error('--admin-token or TELEGRAPH_ADMIN_TOKEN required');
      const client = new TelegraphClient({ server: serverUrl() });
      return out(await client.adminOverview({ adminToken }));
    }
    case 'selftest': {
      // Onboarding confidence check: send a wire to yourself and prove it made
      // the full round trip — encrypted out, stored, fetched, decrypted, and
      // signature-verified. A green result means your keys, registration, and
      // the relay all work end to end. Self-wires are allowed, so this needs no
      // second party. The test wire is acked (cleaned up) at the end.
      const client = loadClient();
      const identity = loadIdentity();
      const steps = [];
      const step = (name, ok, detail) => steps.push({ step: name, ok, detail });
      const nonce = Math.random().toString(36).slice(2, 10);
      const probe = `telegraph selftest ${nonce}`;
      try {
        const me = await client.lookup(identity.address);
        step('registered', me.verified, me.verified ? `@${me.handle}` : 'your directory record did not verify');
        if (!me.verified) throw new Error('not registered or record unverified — run "telegraph signup --handle <name>" first');
        const sent = await client.send(identity.address, probe);
        step('send', true, `wire ${sent.id} sent to self${sent.tokens != null ? ` (${sent.tokens} tokens)` : ''}`);
        const wires = await client.inbox();
        const got = wires.find((w) => w.text === probe);
        step('receive', Boolean(got), got ? 'round-tripped, decrypted' : 'the test wire did not come back');
        step('verify', Boolean(got && got.verified), got && got.verified ? 'sender signature verified' : 'verification failed');
        if (got) await client.ack([got.id]);
        step('cleanup', true, 'test wire acked');
      } catch (err) {
        step('error', false, err.message);
      }
      const ok = steps.every((s) => s.ok);
      out({
        ok,
        address: identity.address,
        server: serverUrl(),
        steps,
        message: ok
          ? '✓ Telegraph is working: a wire went out, came back, decrypted, and verified.'
          : '✗ Self-test failed — see the steps above.',
      });
      if (!ok) process.exitCode = 1;
      return;
    }
    case 'doctor': {
      // Agent-side setup diagnostic: relay, clock, identity, registration,
      // balance. JSON verdict per check; exit 1 if anything fails.
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
        // Signed requests carry a timestamp the relay checks within ±5 min
        // (authWindowMs) — that's the point signed requests actually start
        // failing, so it's the fail threshold here too. Tighter skew than
        // that is fine in practice even if it's not best practice.
        const skewMs = Math.abs(Date.now() - health.now);
        const failsAt = 5 * 60_000;
        add('clock', skewMs < failsAt, skewMs < 60_000
          ? `local/relay skew ${skewMs}ms`
          : skewMs < failsAt
            ? `local/relay skew ${skewMs}ms — still under the ±5 min signing window, but fix this machine's clock before it drifts further`
            : `local/relay skew ${skewMs}ms — signed requests (inbox, send) fail past ±5 min; fix this machine's clock`);
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
      out({ ok, checks });
      // exitCode, not exit(): a hard exit while fetch keep-alive sockets are
      // open crashes Node on Windows (STATUS_STACK_BUFFER_OVERRUN).
      if (!ok) process.exitCode = 1;
      return;
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
