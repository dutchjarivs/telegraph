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
    'telegraph send <TG-address|@handle> <text> [--attach FILE ...] [--expires-in SECONDS] [--thread ID] [--reply-to MSGID] [--priority low|normal|high]': 'send an encrypted wire (text max 4000 chars); --attach seals a file E2E into the wire (repeatable), metered by the standard token formula; threading rides E2E, invisible to the relay',
    'telegraph reply <messageId> <text> [--priority P]': 'reply to a wire in your mailbox: continues its thread and links back to it',
    'telegraph inbox [--ack] [--wait SECONDS] [--save-attachments DIR] [--attachments-base64]': 'fetch (and optionally ack) your wires, decrypted; --wait long-polls; attachments print as {name,mime,size} — add --save-attachments DIR to write the bytes to files, or --attachments-base64 to include them inline',
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
    'telegraph selftest': 'send a test wire to yourself and confirm the full round-trip (send → receive → decrypt → verify) with a green result',
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
      const attachments = readAttachments();
      if (!to || (!text && attachments.length === 0)) {
        throw new Error('usage: telegraph send <TG-address|@handle> <text> [--attach FILE ...]');
      }
      const client = loadClient();
      const sendOpts = threadingOpts();
      if (attachments.length) sendOpts.attachments = attachments;
      return out(await client.send(to, text, sendOpts));
    }
    case 'reply': {
      // Reply to a wire still in your mailbox, by id: continues its thread and
      // links replyTo back to it.
      const [id, ...rest] = opts._;
      const text = rest.join(' ');
      if (!id || !text) throw new Error('usage: telegraph reply <messageId> <text> [--priority low|normal|high]');
      const client = loadClient();
      const wire = (await client.inbox()).find((m) => m.id === String(id));
      if (!wire) throw new Error(`no wire with id ${id} in your mailbox (already acked?) — you can only reply to a wire you still hold`);
      const { priority } = threadingOpts();
      return out(await client.reply(wire, text, priority ? { priority } : {}));
    }
    case 'inbox': {
      const client = loadClient();
      const wait = opts.wait === undefined ? 0 : Number(opts.wait);
      if (!Number.isFinite(wait) || wait < 0) throw new Error('--wait must be seconds (0 or more)');
      const messages = await client.inbox({ ack: Boolean(opts.ack), wait });
      return out({ count: messages.length, acked: Boolean(opts.ack), messages: messages.map(presentMessage) });
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
        for (const m of messages) console.log(JSON.stringify(presentMessage(m)));
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
      return out({ count: messages.length, messages: messages.map(presentMessage) });
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
    case 'selftest': {
      // Send a wire to yourself and prove the full round trip: encrypted out,
      // stored, fetched, decrypted, signature-verified. A green result means
      // your keys, registration, and the relay all work end to end. Self-wires
      // need no second party; the test wire is acked at the end.
      const client = loadClient();
      const identity = loadIdentity();
      const steps = [];
      const step = (name, ok, detail) => steps.push({ step: name, ok, detail });
      const probe = `telegraph selftest ${Math.random().toString(36).slice(2, 10)}`;
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

// Threading flags shared by `send`: --thread, --reply-to, --priority. Only
// present keys are returned so `send` stays a plain message when none are given.
function threadingOpts() {
  const o = {};
  if (opts.thread !== undefined) o.threadId = String(opts.thread);
  if (opts['reply-to'] !== undefined) o.replyTo = String(opts['reply-to']);
  if (opts.priority !== undefined) o.priority = String(opts.priority);
  // Expiry: --expires-at (absolute epoch ms) or --expires-in (relative seconds).
  if (opts['expires-at'] !== undefined) o.expiresAt = Number(opts['expires-at']);
  if (opts['expires-in'] !== undefined) o.ttlMs = Math.round(Number(opts['expires-in']) * 1000);
  return o;
}

// A small extension→MIME map for --attach so a sent file arrives with a sensible
// content type; unknown falls back to octet-stream (bytes are exact regardless).
// Kept inside the helper: main() runs before the top-level consts below, so a
// module-level const here would be in the TDZ when `send` calls it.
function mimeForFile(file) {
  const MIME_BY_EXT = {
    '.txt': 'text/plain', '.md': 'text/markdown', '.json': 'application/json',
    '.csv': 'text/csv', '.html': 'text/html', '.pdf': 'application/pdf',
    '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
    '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
    '.zip': 'application/zip', '.wav': 'audio/wav', '.mp3': 'audio/mpeg',
  };
  return MIME_BY_EXT[path.extname(file).toLowerCase()] ?? 'application/octet-stream';
}

// Read --attach FILE (repeatable) into [{name, mime, data:Buffer}] for send().
function readAttachments() {
  if (opts.attach === undefined) return [];
  const paths = Array.isArray(opts.attach) ? opts.attach : [opts.attach];
  return paths.map((p) => {
    const file = String(p);
    const data = fs.readFileSync(file); // Buffer is a Uint8Array — client accepts it
    return { name: path.basename(file), mime: mimeForFile(file), data };
  });
}

// Make a decrypted message printable as JSON: raw attachment bytes can't live in
// JSON, so each attachment becomes { name, mime, size } plus, on --save-attachments
// DIR, the file path written, and on --attachments-base64, its bytes as base64.
function presentMessage(m) {
  if (!m || !Array.isArray(m.attachments) || m.attachments.length === 0) return m;
  const saveDir = opts['save-attachments'] ? String(opts['save-attachments']) : null;
  if (saveDir) fs.mkdirSync(saveDir, { recursive: true });
  const attachments = m.attachments.map((a, i) => {
    const info = { name: a.name, mime: a.mime, size: a.size };
    if (saveDir) {
      const safe = String(a.name || `attachment-${i + 1}`).replace(/[^A-Za-z0-9._-]/g, '_');
      const dest = path.join(saveDir, `${m.id}--${safe}`);
      fs.writeFileSync(dest, Buffer.from(a.data));
      info.savedPath = dest;
    }
    if (opts['attachments-base64']) info.dataBase64 = Buffer.from(a.data).toString('base64');
    return info;
  });
  return { ...m, attachments };
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
  // A flag repeated on one line accumulates into an array (e.g. --attach a
  // --attach b) — backward compatible since no existing flag is passed twice.
  const set = (key, val) => {
    if (key in o) o[key] = Array.isArray(o[key]) ? [...o[key], val] : [o[key], val];
    else o[key] = val;
  };
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      if (eq !== -1) {
        set(a.slice(2, eq), a.slice(eq + 1));
      } else if (i + 1 < args.length && !args[i + 1].startsWith('--')) {
        set(a.slice(2), args[++i]);
      } else {
        o[a.slice(2)] = true;
      }
    } else {
      o._.push(a);
    }
  }
  return o;
}
