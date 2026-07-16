// Outbound webhook delivery — the hardened path that turns a stored wire into a
// push notification. Every attempt is SSRF-vetted (see ssrf.js) and the socket
// is pinned to a resolved-and-vetted IP so a hostname can't rebind to a private
// address between the check and the connect.
//
// Notify-only by design: the payload carries no ciphertext, only the metadata
// the recipient already sees in their inbox — { event, to, from, id, ts }. A
// leaked or misdelivered webhook therefore exposes nothing the recipient's
// inbox wouldn't. The receiver still calls GET /v1/inbox to fetch and decrypt.
import https from 'node:https';
import crypto from 'node:crypto';
import dns from 'node:dns';
import { parseWebhookUrl, isBlockedIp, ipVersion } from './ssrf.js';

export const WEBHOOK_BODY_CAP = 16 * 1024; // cap the response body we'll read
export const WEBHOOK_TIMEOUT_MS = 3000;

// HMAC-SHA256 the exact bytes we send, so the receiver can prove the call came
// from someone holding the shared secret (i.e. this relay) and wasn't forged or
// tampered. Returned as "sha256=<hex>" — the shape GitHub-style receivers expect.
export function signPayload(bodyStr, secret) {
  return 'sha256=' + crypto.createHmac('sha256', secret).update(bodyStr).digest('hex');
}

// Resolve a hostname and return one vetted IP to pin the connection to, or throw
// with a `.reason` if every resolved address is in a blocked range. An IP
// literal skips DNS. `allowPrivate` (tests only) bypasses the range check so a
// loopback receiver can exercise the delivery mechanics.
export async function resolveVettedIp(hostname, { lookup = dns.lookup, allowPrivate = false } = {}) {
  if (ipVersion(hostname)) {
    if (!allowPrivate && isBlockedIp(hostname)) {
      throw reason('blocked_ip', `webhook host ${hostname} is in a blocked range`);
    }
    return hostname;
  }
  const all = await new Promise((resolve, reject) => {
    lookup(hostname, { all: true }, (err, addrs) => (err ? reject(err) : resolve(addrs)));
  });
  const list = Array.isArray(all) ? all : [];
  if (!list.length) throw reason('no_address', `webhook host ${hostname} did not resolve`);
  // Every resolved address must be safe — a host that returns one public and one
  // private A record must not be usable to reach the private one.
  for (const a of list) {
    if (!allowPrivate && isBlockedIp(a.address)) {
      throw reason('blocked_ip', `webhook host ${hostname} resolved to blocked ${a.address}`);
    }
  }
  return list[0].address;
}

// The default transport: one HTTPS POST, DNS pinned to `pinnedIp`, no socket
// reuse, hard timeout, response body capped. Resolves { status } for any
// completed response (2xx or not); rejects on transport error/timeout.
function httpsTransport({ href, pinnedIp, headers, body, timeoutMs }) {
  return new Promise((resolve, reject) => {
    const req = https.request(
      href,
      {
        method: 'POST',
        headers,
        agent: false, // no pooled socket that skipped our lookup
        timeout: timeoutMs,
        // Pin the socket to the vetted IP: this is the address actually dialed,
        // so the name cannot rebind to something private after we validated it.
        lookup: (host, opts, cb) => cb(null, pinnedIp, ipVersion(pinnedIp) || 4),
      },
      (res) => {
        let received = 0;
        // Drain (capped) so the socket closes cleanly; we don't use the body.
        res.on('data', (c) => {
          received += c.length;
          if (received > WEBHOOK_BODY_CAP) res.destroy();
        });
        res.on('end', () => resolve({ status: res.statusCode }));
        res.on('error', reject);
      },
    );
    req.on('timeout', () => req.destroy(reason('timeout', 'webhook request timed out')));
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// Deliver one notification. Vets the URL and the resolved IP, signs the body,
// and POSTs it. Returns { ok, status } — ok is true only on a 2xx. Throws (with
// `.reason`) when the target is refused (not https, blocked IP, DNS failure) or
// the transport fails; the caller decides whether to retry.
export async function deliverOnce(url, payloadObj, {
  secret,
  timeoutMs = WEBHOOK_TIMEOUT_MS,
  transport = httpsTransport,
  lookup = dns.lookup,
  allowPrivate = false,
  deliveryId = '',
} = {}) {
  const { hostname, href } = parseWebhookUrl(url); // throws on not-https/blocked-literal
  const pinnedIp = await resolveVettedIp(hostname, { lookup, allowPrivate });
  const body = JSON.stringify(payloadObj);
  const headers = {
    'content-type': 'application/json',
    'user-agent': 'telegraph-relay-webhook/1',
    'x-telegraph-event': payloadObj.event ?? 'wire.received',
    'x-telegraph-delivery': deliveryId,
    ...(secret ? { 'x-telegraph-signature': signPayload(body, secret) } : {}),
  };
  const { status } = await transport({ href, pinnedIp, headers, body, timeoutMs });
  return { ok: status >= 200 && status < 300, status };
}

function reason(code, message) {
  const e = new Error(message);
  e.reason = code;
  return e;
}
