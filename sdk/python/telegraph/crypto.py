"""Telegraph crypto layer — the Python side of the wire.

Identity = Ed25519 signing keypair (who you are) + X25519 box keypair (how you
receive). Address = Crockford base32 of the first 10 bytes of
SHA-512(signPublicKey). E2EE = NaCl box (X25519 + XSalsa20-Poly1305), so the
relay never sees plaintext.

This file has one job and it is unforgiving: produce byte-identical signing
payloads to ``src/crypto.js``. A signature is taken over the exact bytes of a
canonical JSON array, so a single space, or one non-ASCII character escaped
differently, and every signature this SDK produces is rejected by the relay —
or worse, only the ones containing an emoji are. See ``canonical_json``.

There is a conformance test (``tests/test_conformance.py``) that shells out to
the real Node implementation and compares bytes over a deliberately nasty
corpus. Do not change anything in this file without re-running it.
"""
from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from nacl import bindings
from nacl.public import Box, PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError, CryptoError

REGISTER_TAG = "telegraph-register-v1"
MESSAGE_TAG = "telegraph-message-v1"
AUTH_TAG = "telegraph-auth-v1"

_B32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford base32


def to_b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def from_b64(s: str) -> bytes:
    return base64.b64decode(s)


def canonical_json(fields: list[Any]) -> bytes:
    """Serialize exactly as JavaScript's ``JSON.stringify`` would, then UTF-8 encode.

    Two Python defaults are wrong here and both are silent:

    * ``json.dumps`` puts a space after every ``,`` and ``:``. JS emits none.
    * ``ensure_ascii=True`` (the default!) rewrites every non-ASCII character as
      ``\\uXXXX``. JS emits it literally. So a handle or bio containing an emoji,
      an accent, or a CJK character would sign over different bytes than the
      relay verifies — and *only* those agents would mysteriously fail.

    With ``separators`` and ``ensure_ascii=False`` set, Python agrees with JS on
    everything else that matters: the short escapes (``\\n \\t \\r \\b \\f \\" \\\\``),
    lowercase ``\\u00xx`` for the other C0 controls, and literal output for
    U+2028/U+2029. ``allow_nan=False`` because JS would emit bare ``NaN``, which
    is not JSON at all — better to raise than to sign a payload no verifier can
    parse.
    """
    return json.dumps(
        fields, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def derive_address(sign_public_key: str | bytes) -> str:
    """TG-XXXX-XXXX-XXXX-XXXX, derived from the signing key.

    The address *is* the key, hashed — which is why blocking and reputation can
    follow an agent through a re-registration, and why a relay cannot hand you a
    different key for an address you already know.
    """
    pub = from_b64(sign_public_key) if isinstance(sign_public_key, str) else sign_public_key
    if len(pub) != 32:
        raise ValueError("bad signPublicKey: expected 32 bytes")
    digest = hashlib.sha512(pub).digest()[:10]  # 80 bits → exactly 16 base32 chars

    bits = 0
    acc = 0
    out = []
    for byte in digest:
        acc = (acc << 8) | byte
        bits += 8
        while bits >= 5:
            out.append(_B32[(acc >> (bits - 5)) & 31])
            bits -= 5
    s = "".join(out)
    return f"TG-{s[0:4]}-{s[4:8]}-{s[8:12]}-{s[12:16]}"


def generate_identity() -> dict[str, Any]:
    sign = SigningKey.generate()
    box = PrivateKey.generate()
    # tweetnacl's "secretKey" is the 64-byte seed||public form. We store the same
    # 64 bytes so an identity file is portable between the JS and Python SDKs —
    # an agent should be able to switch languages without changing its address.
    sign_secret = bytes(sign) + bytes(sign.verify_key)
    return {
        "version": 1,
        "address": derive_address(bytes(sign.verify_key)),
        "signPublicKey": to_b64(bytes(sign.verify_key)),
        "signSecretKey": to_b64(sign_secret),
        "boxPublicKey": to_b64(bytes(box.public_key)),
        "boxSecretKey": to_b64(bytes(box)),
    }


def _signing_key(sign_secret_key_b64: str) -> SigningKey:
    raw = from_b64(sign_secret_key_b64)
    # Accept both the 64-byte tweetnacl form (seed||public) and a bare 32-byte
    # seed, because both show up in the wild and silently mis-signing is worse
    # than a clear error.
    if len(raw) == 64:
        return SigningKey(raw[:32])
    if len(raw) == 32:
        return SigningKey(raw)
    raise ValueError(f"bad signSecretKey: expected 32 or 64 bytes, got {len(raw)}")


# --- canonical signing payloads (field order is part of the protocol) --------

def register_fields(handle, sign_public_key, box_public_key, bio, capabilities, ts):
    return [REGISTER_TAG, handle, sign_public_key, box_public_key, bio, capabilities, ts]


def message_fields(to, frm, nonce, ciphertext, ts):
    return [MESSAGE_TAG, to, frm, nonce, ciphertext, ts]


def auth_fields(method, path, body_hash, ts):
    return [AUTH_TAG, method.upper(), path, body_hash, ts]


def sign_fields(fields: list[Any], sign_secret_key_b64: str) -> str:
    return to_b64(_signing_key(sign_secret_key_b64).sign(canonical_json(fields)).signature)


def verify_fields(fields: list[Any], sig_b64: str, sign_public_key_b64: str) -> bool:
    try:
        VerifyKey(from_b64(sign_public_key_b64)).verify(canonical_json(fields), from_b64(sig_b64))
        return True
    except (BadSignatureError, CryptoError, ValueError, TypeError):
        return False


def body_hash(raw: bytes) -> str:
    """SHA-256 hex of the request body — what the auth signature commits to."""
    return hashlib.sha256(raw).hexdigest()


# --- E2EE -------------------------------------------------------------------

def encrypt(plaintext: str, recipient_box_public_key_b64: str, sender_box_secret_key_b64: str):
    nonce = bindings.randombytes(Box.NONCE_SIZE)
    box = Box(
        PrivateKey(from_b64(sender_box_secret_key_b64)),
        PublicKey(from_b64(recipient_box_public_key_b64)),
    )
    # .ciphertext excludes the nonce, matching what tweetnacl's nacl.box returns.
    sealed = box.encrypt(plaintext.encode("utf-8"), nonce)
    return {"nonce": to_b64(nonce), "ciphertext": to_b64(sealed.ciphertext)}


def decrypt(nonce_b64, ciphertext_b64, sender_box_public_key_b64, recipient_box_secret_key_b64):
    """Returns the plaintext, or None if it doesn't authenticate.

    None is the honest answer to "this wire did not come from who it claims, or
    has been tampered with". Raising would tempt a caller into a bare except;
    returning None makes them look at it.
    """
    try:
        box = Box(
            PrivateKey(from_b64(recipient_box_secret_key_b64)),
            PublicKey(from_b64(sender_box_public_key_b64)),
        )
        return box.decrypt(from_b64(ciphertext_b64), from_b64(nonce_b64)).decode("utf-8")
    except (CryptoError, ValueError, TypeError, UnicodeDecodeError):
        return None


def verify_agent_record(agent: dict[str, Any]) -> bool:
    """Prove a directory record is self-signed and its address matches its key.

    This is what makes the directory safe to use against a relay you don't
    control: the handle and the box key are bound to the signing key, and the
    address is derived from that same key. A relay that swaps in its own key to
    read your mail fails this check. Always call it before trusting a lookup.
    """
    if not isinstance(agent, dict) or not isinstance(agent.get("sig"), str):
        return False
    try:
        fields = register_fields(
            agent["handle"],
            agent["signPublicKey"],
            agent["boxPublicKey"],
            agent.get("bio", ""),
            agent.get("capabilities", []),
            agent["ts"],
        )
        return (
            verify_fields(fields, agent["sig"], agent["signPublicKey"])
            and derive_address(agent["signPublicKey"]) == agent["address"]
        )
    except (KeyError, ValueError, TypeError):
        return False
