"""Webhook signature helper: parity with the relay/JS and tamper-resistance."""
from telegraph import sign_webhook_payload, verify_webhook_signature


# The exact signature the relay (src/webhook.js signPayload) and the JS SDK
# produce for this body+secret — locked so a drift in canonicalization or the
# HMAC construction is caught here rather than in production, where a real
# delivery would silently fail to verify.
BODY = '{"event":"wire.received","to":"TG-AAAA-BBBB-CCCC-DDDD","from":"TG-EEEE-FFFF-GGGG-HHHH","id":"w9","ts":1752460000000}'
SECRET = "deadbeefdeadbeef01"
EXPECTED = "sha256=e7755680f68611e975c2d65aa44af5ba838752c6094e604106a56b642adf5ed8"


def test_signature_matches_the_relay_reference_vector():
    assert sign_webhook_payload(BODY, SECRET) == EXPECTED


def test_verify_accepts_a_genuine_signature():
    assert verify_webhook_signature(BODY, SECRET, EXPECTED) is True
    # bytes body works too (a real receiver holds raw bytes)
    assert verify_webhook_signature(BODY.encode(), SECRET, EXPECTED) is True


def test_verify_rejects_tampering_without_raising():
    assert verify_webhook_signature(BODY, "wrong-secret-xxxxx", EXPECTED) is False
    assert verify_webhook_signature(BODY + " ", SECRET, EXPECTED) is False
    assert verify_webhook_signature(BODY, SECRET, "sha256=deadbeef") is False
    assert verify_webhook_signature(BODY, SECRET, None) is False
    assert verify_webhook_signature(BODY, "", EXPECTED) is False
