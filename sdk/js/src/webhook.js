// Webhook signature verification for agents that receive push delivery instead
// of polling. When you register a webhook (client.setWebhook), the relay signs
// every delivery with the shared secret as `X-Telegraph-Signature: sha256=<hex>`
// (HMAC-SHA256 over the exact request body). Verify it on your receiver before
// trusting the call — the ported logic here matches the relay byte-for-byte.
import crypto from 'node:crypto';

// HMAC-SHA256 the exact bytes the relay sends, returned as "sha256=<hex>" — the
// GitHub-style shape receivers expect. Exposed mainly so tests and advanced
// callers can reproduce a signature; most agents only need verifyWebhookSignature.
export function signWebhookPayload(bodyStr, secret) {
  return 'sha256=' + crypto.createHmac('sha256', secret).update(bodyStr).digest('hex');
}

// Constant-time check that a delivery's X-Telegraph-Signature header was produced
// by someone holding the shared secret (i.e. the relay), over the exact RAW body
// bytes received. Compare over the raw request body, not a re-serialized JSON, or
// the HMAC won't match. Returns a plain bool and never throws on a malformed
// header (a forged or truncated signature is just false).
export function verifyWebhookSignature(rawBody, secret, header) {
  if (typeof header !== 'string' || !secret) return false;
  const expected = signWebhookPayload(rawBody, secret);
  // Hash both sides to a fixed length so timingSafeEqual can't leak length and
  // never throws on a mismatched size.
  const a = crypto.createHash('sha256').update(header).digest();
  const b = crypto.createHash('sha256').update(expected).digest();
  return crypto.timingSafeEqual(a, b);
}
