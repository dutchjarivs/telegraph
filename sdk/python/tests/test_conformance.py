"""Byte-level conformance against the real JavaScript implementation.

Everything in the Python SDK rests on one claim: that ``canonical_json`` produces
the same bytes as JavaScript's ``JSON.stringify``. If it doesn't, signatures made
here are rejected by the relay — and the failure would be *selective*, hitting
only agents whose handle or bio happens to contain the character that diverges.
That is precisely the kind of bug that ships.

So this doesn't reason about it. It shells out to the actual ``src/crypto.js``
and compares bytes, over a corpus chosen to hurt: emoji, CJK, accents, quotes,
backslashes, newlines, C0 control characters, and the two line separators that
have historically split JSON implementations.
"""
from __future__ import annotations

import json
import pathlib
import subprocess

import pytest

from telegraph.crypto import (
    canonical_json,
    derive_address,
    decrypt,
    generate_identity,
    receipt_fields,
    register_fields,
    sign_fields,
    verify_fields,
)

HERE = pathlib.Path(__file__).parent
VECTORS_JS = HERE / "vectors.js"


def node(payload: dict) -> dict:
    proc = subprocess.run(
        ["node", str(VECTORS_JS)],
        input=json.dumps(payload).encode("utf-8"),
        capture_output=True,
        check=True,
    )
    return json.loads(proc.stdout)


# Each of these has broken a cross-language JSON implementation somewhere.
NASTY = [
    ["telegraph-register-v1", "plain-handle", "", [], 1752460000000],
    ["quote\"inside", "back\\slash", "tab\there"],
    ["newline\nhere", "carriage\rreturn", "form\ffeed", "back\bspace"],
    ["null byte \x00 and \x01 \x1f", "del \x7f"],
    # ensure_ascii=True (Python's default!) would escape every one of these.
    ["émoji 🤠 and accents: café", "CJK: 電報", "русский", "עברית"],
    ["math: 𝔞𝔟 (astral plane)", "🇺🇸 flag (surrogate pair)"],
    # U+2028/U+2029: JSON.stringify emits them literally; some libraries escape.
    ["line sep", "para sep"],
    ["", " ", "   leading and trailing   "],
    ["mixed: \"🤠\"\n\\ 電報 \x1f"],
    [1752460000000, 0, -1, 9007199254740991],
    ["telegraph-auth-v1", "POST", "/v1/send", "a" * 64, 1752460000000],
    ["caps", ["array", "of", "strings"], []],
]


def test_canonical_json_matches_javascript_byte_for_byte():
    out = node({"canonical": NASTY})
    for fields, expected_hex in zip(NASTY, out["canonical"]):
        got = canonical_json(fields).hex()
        assert got == expected_hex, (
            f"canonical JSON diverged from JavaScript for {fields!r}\n"
            f"  js:     {bytes.fromhex(expected_hex)!r}\n"
            f"  python: {canonical_json(fields)!r}"
        )


def test_canonical_json_has_no_incidental_whitespace():
    # The single most likely way to get this wrong, called out on its own so the
    # failure message says what actually happened.
    assert canonical_json(["a", "b", 1]) == b'["a","b",1]'


def test_canonical_json_refuses_nan_rather_than_signing_it():
    # JS would happily stringify NaN as a bare `NaN`, which isn't JSON — nothing
    # downstream could parse the payload it signed. Fail loudly instead.
    with pytest.raises(ValueError):
        canonical_json([float("nan")])


def test_address_derivation_agrees_with_javascript():
    out = node({"identity": True, "sign": []})
    identity = out["identity"]
    assert derive_address(identity["signPublicKey"]) == out["address"]
    # And the identity JS generated is self-consistent under our derivation.
    assert derive_address(identity["signPublicKey"]) == identity["address"]


def test_python_verifies_signatures_made_by_javascript():
    to_sign = [
        register_fields("interop", "PK", "BK", "bio with 🤠 and \"quotes\"", ["a", "b"], 1752460000000),
        ["telegraph-auth-v1", "POST", "/v1/send", "deadbeef", 1752460000000],
        receipt_fields("wire-123", "TG-AAAA-BBBB-CCCC-DDDD", "TG-EEEE-FFFF-GGGG-HHHH", 1752460000000),
    ]
    out = node({"identity": True, "sign": to_sign})
    identity, sigs = out["identity"], out["signatures"]

    for fields, sig in zip(to_sign, sigs):
        assert verify_fields(fields, sig, identity["signPublicKey"]), f"failed to verify JS signature over {fields!r}"


def test_javascript_and_python_produce_identical_signatures():
    # Ed25519 is deterministic, so the same key over the same bytes must give the
    # same signature. If canonical JSON diverges anywhere, this is where it shows.
    to_sign = [register_fields("determinism", "PK", "BK", "🤠 café 電報", [], 1752460000000)]
    out = node({"identity": True, "sign": to_sign})
    ours = sign_fields(to_sign[0], out["identity"]["signSecretKey"])
    assert ours == out["signatures"][0]


def test_python_decrypts_a_wire_sealed_by_javascript():
    me = generate_identity()
    out = node({"encryptTo": {"plaintext": "sealed in JS, opened in Python 🤠", "boxPublicKey": me["boxPublicKey"]}})
    sealed = out["sealed"]
    text = decrypt(sealed["nonce"], sealed["ciphertext"], sealed["senderBoxPublicKey"], me["boxSecretKey"])
    assert text == "sealed in JS, opened in Python 🤠"


def test_a_tampered_wire_decrypts_to_none_rather_than_garbage():
    me = generate_identity()
    out = node({"encryptTo": {"plaintext": "authentic", "boxPublicKey": me["boxPublicKey"]}})
    sealed = out["sealed"]

    # Flip a byte in the ciphertext. Poly1305 must catch it.
    raw = bytearray(__import__("base64").b64decode(sealed["ciphertext"]))
    raw[0] ^= 0x01
    tampered = __import__("base64").b64encode(bytes(raw)).decode()

    assert decrypt(sealed["nonce"], tampered, sealed["senderBoxPublicKey"], me["boxSecretKey"]) is None
    # And a wire from someone else's key doesn't open either.
    other = generate_identity()
    assert decrypt(sealed["nonce"], sealed["ciphertext"], other["boxPublicKey"], me["boxSecretKey"]) is None


def test_an_identity_generated_in_python_is_valid_in_javascript():
    # The 64-byte seed||public secret-key form is what makes an identity file
    # portable between the two SDKs. An agent must be able to switch languages
    # without changing its address — the address is its phone number.
    me = generate_identity()
    fields = register_fields("portable", me["signPublicKey"], me["boxPublicKey"], "", [], 1752460000000)
    sig = sign_fields(fields, me["signSecretKey"])

    verified = subprocess.run(
        ["node", "--input-type=module", "-e", """
        import { verifyFields, deriveAddress } from '../../../src/crypto.js';
        const [fields, sig, pk, addr] = JSON.parse(process.argv[1]);
        const ok = verifyFields(fields, sig, pk) && deriveAddress(pk) === addr;
        process.stdout.write(ok ? 'ok' : 'no');
        """, json.dumps([fields, sig, me["signPublicKey"], me["address"]])],
        capture_output=True, check=True, cwd=HERE,
    )
    assert verified.stdout == b"ok", verified.stderr.decode()
