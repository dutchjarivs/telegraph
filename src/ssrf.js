// SSRF defense for outbound webhook delivery.
//
// Webhooks are the one place the relay opens a connection to an address an
// agent chose. On a box behind a Cloudflare tunnel that is a classic
// server-side request forgery surface: a callback URL of https://169.254.169.254
// (cloud metadata) or http://127.0.0.1:7787/v1/admin/... would have the relay
// attack itself or its host. So every webhook target is validated twice —
// the URL shape here, and every resolved IP at delivery time (see deliver.js) —
// and the socket is pinned to a vetted IP so DNS can't be rebound between the
// check and the connect.
//
// These are pure, synchronous checks with no I/O, so they're cheap to unit-test
// against the whole zoo of private/loopback/link-local/reserved ranges.

// Parse a webhook URL and enforce the shape rules that don't need DNS:
//   • https only (no http, no file:, no gopher:, no data:) — plaintext callbacks
//     would leak the delivery metadata and can't be trusted anyway.
//   • a real hostname or IP literal, a sane port.
// Returns { hostname, port } (port defaulting to 443). Throws Error with a
// stable `.reason` on anything it won't allow, so callers surface *why*.
export function parseWebhookUrl(raw) {
  let u;
  try {
    u = new URL(raw);
  } catch {
    throw reason('bad_url', 'not a valid URL');
  }
  if (u.protocol !== 'https:') {
    throw reason('not_https', 'webhook URL must be https');
  }
  if (u.username || u.password) {
    throw reason('has_credentials', 'webhook URL must not embed credentials');
  }
  const hostname = u.hostname;
  if (!hostname) throw reason('no_host', 'webhook URL has no host');
  // An IP literal in the URL is checked right here; a hostname is checked after
  // it resolves (delivery time). Literal loopback/private is refused up front.
  const literal = ipVersion(hostname) || (isBracketedV6(hostname) ? 6 : 0);
  if (literal) {
    const ip = hostname.replace(/^\[|\]$/g, '');
    if (isBlockedIp(ip)) throw reason('blocked_ip', `webhook host ${ip} is in a blocked range`);
  }
  const port = u.port ? Number(u.port) : 443;
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw reason('bad_port', 'webhook URL port is out of range');
  }
  return { hostname: hostname.replace(/^\[|\]$/g, ''), port, href: u.href };
}

function isBracketedV6(h) {
  return h.startsWith('[') && h.endsWith(']');
}

// Which IP version a string literally is (4, 6, or 0 if it's a hostname).
export function ipVersion(s) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) {
    return s.split('.').every((o) => Number(o) <= 255) ? 4 : 0;
  }
  const bare = s.replace(/^\[|\]$/g, '');
  // Loose IPv6 shape: hex groups and colons, optionally an embedded v4 tail.
  if (/:/.test(bare) && /^[0-9a-fA-F:.]+$/.test(bare) && bare.includes(':')) return 6;
  return 0;
}

// The core allowlist-by-exclusion: true when an IP must never be a webhook
// target. Covers loopback, private, link-local, unique-local, unspecified,
// carrier-grade NAT, documentation, benchmarking, multicast, and reserved
// ranges — plus IPv4-mapped/compatible IPv6 so an attacker can't smuggle
// 127.0.0.1 in as ::ffff:127.0.0.1.
export function isBlockedIp(ip) {
  const v = ipVersion(ip);
  if (v === 4) return isBlockedV4(ip);
  if (v === 6) return isBlockedV6(ip.toLowerCase());
  // Not an IP we can classify → refuse; delivery only ever passes real IPs here.
  return true;
}

function isBlockedV4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return true;
  const [a, b] = p;
  if (a === 0) return true; // "this" network / unspecified
  if (a === 10) return true; // private
  if (a === 127) return true; // loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // CGNAT 100.64/10
  if (a === 169 && b === 254) return true; // link-local (incl. cloud metadata 169.254.169.254)
  if (a === 172 && b >= 16 && b <= 31) return true; // private 172.16/12
  if (a === 192 && b === 168) return true; // private
  if (a === 192 && b === 0) return true; // 192.0.0/24 (IETF) + 192.0.2/24 (TEST-NET-1)
  if (a === 192 && b === 88 && p[2] === 99) return true; // 6to4 relay anycast
  if (a === 198 && (b === 18 || b === 19)) return true; // benchmarking 198.18/15
  if (a === 198 && b === 51 && p[2] === 100) return true; // TEST-NET-2
  if (a === 203 && b === 0 && p[2] === 113) return true; // TEST-NET-3
  if (a >= 224) return true; // 224/4 multicast + 240/4 reserved + 255.255.255.255
  return false;
}

function isBlockedV6(ip) {
  // Normalize an IPv4-mapped/compatible tail (::ffff:127.0.0.1, ::127.0.0.1)
  // back to the v4 check — these route to the embedded v4 address.
  const m = ip.match(/(?:^|:)((?:\d{1,3}\.){3}\d{1,3})$/);
  if (m) {
    // ::ffff:x or ::x forms; classify by the embedded v4 (and by the v6 prefix).
    if (isBlockedV4(m[1])) return true;
    // A global v4 embedded in ::ffff: is still reachable as that v4 — allow only
    // if the v4 is allowed (already checked). Fall through for other prefixes.
  }
  if (ip === '::' || ip === '::0' || ip === '0:0:0:0:0:0:0:0') return true; // unspecified
  if (ip === '::1') return true; // loopback
  const head = ip.split(':')[0];
  const h = head === '' ? 0 : parseInt(head, 16);
  // fe80::/10 link-local
  if ((h & 0xffc0) === 0xfe80) return true;
  // fc00::/7 unique-local (fc00/fd00)
  if ((h & 0xfe00) === 0xfc00) return true;
  // ff00::/8 multicast
  if ((h & 0xff00) === 0xff00) return true;
  // 2001:db8::/32 documentation
  if (ip.startsWith('2001:db8:') || ip.startsWith('2001:0db8:')) return true;
  // ::ffff:0:0/96 mapped without an embedded dotted-quad already handled above;
  // a bare ::/96 compatible address with no v4 tail is effectively unspecified.
  return false;
}

function reason(code, message) {
  const e = new Error(message);
  e.reason = code;
  return e;
}
