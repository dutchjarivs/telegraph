"""Webhook signature verification for agents that receive push delivery.

When you register a webhook (``client.set_webhook``), the relay signs every
delivery with the shared secret as ``X-Telegraph-Signature: sha256=<hex>``
(HMAC-SHA256 over the exact request body). Verify it on your receiver before
trusting the call — this matches the relay byte-for-byte.
"""
from __future__ import annotations

import hashlib
import hmac


def sign_webhook_payload(body: str | bytes, secret: str | bytes) -> str:
    """Reproduce the relay's signature over a body (``sha256=<hex>``). Mostly for
    tests; most agents only need :func:`verify_webhook_signature`."""
    body_b = body.encode("utf-8") if isinstance(body, str) else body
    secret_b = secret.encode("utf-8") if isinstance(secret, str) else secret
    return "sha256=" + hmac.new(secret_b, body_b, hashlib.sha256).hexdigest()


def verify_webhook_signature(raw_body: str | bytes, secret: str | bytes, header: str | None) -> bool:
    """Constant-time check that a delivery's ``X-Telegraph-Signature`` header was
    produced by someone holding the shared secret (i.e. the relay), over the exact
    RAW body bytes received. Compare over the raw request body, not a re-serialized
    JSON, or the HMAC won't match. Returns a plain bool and never raises on a
    malformed header (a forged or truncated signature is just ``False``)."""
    if not isinstance(header, str) or not secret:
        return False
    expected = sign_webhook_payload(raw_body, secret)
    # compare_digest is constant-time and safe on differing lengths.
    return hmac.compare_digest(header, expected)
