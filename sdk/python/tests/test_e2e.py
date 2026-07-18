"""Live interop against a real Node relay.

The conformance tests prove the crypto agrees at the byte level. These prove the
whole thing actually works: a real relay process, on a real port, with a Python
agent and a JavaScript agent talking to each other in both directions.

This is the test that would have caught every integration bug I could have
written — a wrong header name, a signature over the query string, a body hashed
after re-serialization. None of those show up in a unit test with a mocked
transport, which is why there isn't one.
"""
from __future__ import annotations

import json
import os
import pathlib
import shutil
import socket
import subprocess
import tempfile
import time

import pytest

from telegraph import TelegraphClient, TelegraphError

REPO = pathlib.Path(__file__).resolve().parents[3]  # …/telegraph


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(scope="module")
def relay():
    """A real relay process, on a throwaway data directory.

    Booted via tests/relay.js rather than `telegraph serve`, so the anti-sybil
    registration cap (5/IP/hour in production) can be raised for the harness
    without touching the relay's real defaults.
    """
    data_dir = tempfile.mkdtemp(prefix="telegraph-pysdk-")
    proc = subprocess.Popen(
        ["node", str(pathlib.Path(__file__).parent / "relay.js"), data_dir],
        cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        env={**os.environ, "TELEGRAPH_ADMIN_TOKEN": ""},
    )

    # The relay prints the port it bound. Read it rather than guessing — picking
    # a free port and hoping nothing takes it first is a flaky test waiting.
    line = proc.stdout.readline()
    if not line:
        raise RuntimeError("relay died on startup")
    port = json.loads(line)["port"]
    base = f"http://127.0.0.1:{port}"

    deadline = time.time() + 20
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("relay died on startup")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("relay never came up")

    yield base

    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
    shutil.rmtree(data_dir, ignore_errors=True)


def node_client_script(base: str, identity: dict, script: str) -> dict:
    """Run a snippet against the *JavaScript* SDK, so both sides are exercised."""
    proc = subprocess.run(
        ["node", "--input-type=module", "-e", f"""
        import {{ TelegraphClient }} from './src/client.js';
        const identity = JSON.parse(process.argv[1]);
        const tg = new TelegraphClient({{ server: '{base}', identity }});
        {script}
        """, json.dumps(identity)],
        cwd=REPO, capture_output=True, check=True,
    )
    return json.loads(proc.stdout or b"{}")


def test_python_agent_registers_and_the_relay_accepts_its_signature(relay):
    # If canonical JSON were wrong by a single byte, this is where it dies:
    # the relay verifies the registration signature over those exact bytes.
    tg = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    res = tg.register(handle="py-first", bio="registered from Python 🤠", capabilities=["test"])
    assert res.get("ok") or res.get("agent") or res.get("address"), res

    # And the record we get back is self-signed and key-bound — which is what
    # makes it safe to trust a directory served by a relay you don't control.
    me = tg.lookup("@py-first")
    assert me["verified"] is True
    assert me["address"] == tg.identity["address"]
    assert me["bio"] == "registered from Python 🤠"


def test_python_sends_and_javascript_reads_it(relay):
    py = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    js_identity = TelegraphClient.generate_identity()
    js = TelegraphClient(relay, identity=js_identity)

    py.register(handle="py-sender")
    js.register(handle="js-reader")

    body = "from Python to JavaScript — 🤠 café 電報"
    py.send("@js-reader", body)

    # Read it with the *real* JavaScript SDK, not with Python.
    out = node_client_script(relay, js_identity, """
        const msgs = await tg.inbox();
        process.stdout.write(JSON.stringify(msgs.map((m) => ({
          text: m.text, verified: m.verified, fromHandle: m.fromHandle,
        }))));
    """)
    assert len(out) == 1
    assert out[0]["text"] == body, "JavaScript could not decrypt what Python sealed"
    assert out[0]["verified"] is True, "JavaScript could not verify Python's signature"
    assert out[0]["fromHandle"] == "py-sender"


def test_javascript_sends_and_python_reads_it(relay):
    py_identity = TelegraphClient.generate_identity()
    py = TelegraphClient(relay, identity=py_identity)
    js_identity = TelegraphClient.generate_identity()

    py.register(handle="py-reader")
    TelegraphClient(relay, identity=js_identity).register(handle="js-sender")

    body = "from JavaScript to Python — \" quotes \\ backslash \n newline"
    node_client_script(relay, js_identity, f"""
        await tg.send('@py-reader', {json.dumps(body)});
        process.stdout.write('{{}}');
    """)

    msgs = py.inbox()
    assert len(msgs) == 1
    assert msgs[0].text == body, "Python could not decrypt what JavaScript sealed"
    assert msgs[0].verified is True, "Python could not verify JavaScript's signature"
    assert msgs[0].from_handle == "js-sender"


def test_python_threads_and_javascript_reads_the_thread(relay):
    """A threaded wire packed in Python must unpack in the JavaScript SDK."""
    py = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    js_identity = TelegraphClient.generate_identity()
    js = TelegraphClient(relay, identity=js_identity)
    py.register(handle="py-thr-sender")
    js.register(handle="js-thr-reader")  # register() advertises wire-envelope-v1

    sent = py.send("@js-thr-reader", "threaded from python", thread_id="cross-1", priority="high")
    assert sent["threadingApplied"] is True

    out = node_client_script(relay, js_identity, """
        const msgs = await tg.inbox();
        process.stdout.write(JSON.stringify(msgs.map((m) => ({
          text: m.text, threadId: m.threadId, priority: m.priority, verified: m.verified,
        }))));
    """)
    assert len(out) == 1
    assert out[0]["text"] == "threaded from python"
    assert out[0]["threadId"] == "cross-1"
    assert out[0]["priority"] == "high"
    assert out[0]["verified"] is True


def test_javascript_threads_and_python_reads_the_thread(relay):
    """And the other direction: JS packs the envelope, Python unpacks it."""
    py_identity = TelegraphClient.generate_identity()
    py = TelegraphClient(relay, identity=py_identity)
    js_identity = TelegraphClient.generate_identity()
    py.register(handle="py-thr-reader")  # advertises the capability
    TelegraphClient(relay, identity=js_identity).register(handle="js-thr-sender")

    node_client_script(relay, js_identity, """
        await tg.send('@py-thr-reader', 'threaded from js', { threadId: 'cross-2', replyTo: 'M-42', priority: 'low' });
        process.stdout.write('{}');
    """)

    msgs = py.inbox()
    assert len(msgs) == 1
    assert msgs[0].text == "threaded from js"
    assert msgs[0].thread_id == "cross-2"
    assert msgs[0].reply_to == "M-42"
    assert msgs[0].priority == "low"
    assert msgs[0].verified is True


def test_python_attaches_and_javascript_reads_the_file(relay):
    """A file attached in Python must decrypt byte-for-byte in the JavaScript SDK.
    Small payload so the sealed wire fits the relay's default 16 KB cap."""
    py = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    js_identity = TelegraphClient.generate_identity()
    js = TelegraphClient(relay, identity=js_identity)
    py.register(handle="py-att-sender")
    js.register(handle="js-att-reader")  # register() advertises attachments-v1

    payload = bytes([0, 1, 2, 250, 255])
    sent = py.send("@js-att-reader", "file from python", attachments=[{"name": "p.bin", "mime": "application/octet-stream", "data": payload}])
    assert sent["attachments"] == 1

    out = node_client_script(relay, js_identity, """
        const msgs = await tg.inbox();
        process.stdout.write(JSON.stringify(msgs.map((m) => ({
          text: m.text, verified: m.verified,
          att: m.attachments.map((a) => ({ name: a.name, mime: a.mime, size: a.size, bytes: [...a.data] })),
        }))));
    """)
    assert len(out) == 1
    assert out[0]["text"] == "file from python"
    assert out[0]["verified"] is True
    assert len(out[0]["att"]) == 1
    assert out[0]["att"][0]["name"] == "p.bin"
    assert out[0]["att"][0]["size"] == 5
    assert out[0]["att"][0]["bytes"] == [0, 1, 2, 250, 255], "JavaScript decoded different bytes than Python sealed"


def test_javascript_attaches_and_python_reads_the_file(relay):
    """The other direction: JS attaches the file, Python decodes it."""
    py_identity = TelegraphClient.generate_identity()
    py = TelegraphClient(relay, identity=py_identity)
    js_identity = TelegraphClient.generate_identity()
    py.register(handle="py-att-reader")  # advertises attachments-v1
    TelegraphClient(relay, identity=js_identity).register(handle="js-att-sender")

    node_client_script(relay, js_identity, """
        const data = new Uint8Array([9, 8, 7, 6, 0, 255]);
        await tg.send('@py-att-reader', 'file from js', { attachments: [{ name: 'j.bin', mime: 'text/plain', data }] });
        process.stdout.write('{}');
    """)

    msgs = py.inbox()
    assert len(msgs) == 1
    assert msgs[0].text == "file from js"
    assert msgs[0].verified is True
    assert len(msgs[0].attachments) == 1
    assert msgs[0].attachments[0]["name"] == "j.bin"
    assert msgs[0].attachments[0]["mime"] == "text/plain"
    assert msgs[0].attachments[0]["data"] == bytes([9, 8, 7, 6, 0, 255]), "Python decoded different bytes than JavaScript sealed"


def test_attachment_to_an_opted_out_recipient_is_refused(relay):
    a = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    b = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    a.register(handle="py-att-drop-a")
    b.register(handle="py-att-drop-b", attachments=False)  # attachment-unaware peer

    with pytest.raises(TelegraphError):
        a.send("@py-att-drop-b", "file for you", attachments=[{"name": "x", "data": b"\x01\x02"}])
    assert b.inbox() == []  # nothing landed — refused before the send


def test_python_attachment_round_trip_and_sent_history(relay):
    a = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    b = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    a.register(handle="py-att-rt-a")
    b.register(handle="py-att-rt-b")

    a.send("@py-att-rt-b", "with file", attachments=[{"name": "r.bin", "data": b"\x07\x07\x07"}])
    got = b.inbox(ack=True)
    assert got[0].attachments[0]["data"] == b"\x07\x07\x07"
    # The sender's own outbox carries the attachment it sent, decrypted.
    log = a.sent()
    assert log[0].get("attachments") and log[0]["attachments"][0]["data"] == b"\x07\x07\x07"


def test_python_sets_expiry_and_javascript_reads_it(relay):
    """A per-message expiry sealed in Python must surface in the JavaScript SDK."""
    py = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    js_identity = TelegraphClient.generate_identity()
    js = TelegraphClient(relay, identity=js_identity)
    py.register(handle="py-exp-sender")
    js.register(handle="js-exp-reader")

    future = int(time.time() * 1000) + 60_000
    sent = py.send("@js-exp-reader", "expires soon", expires_at=future)
    assert sent["expiresAt"] == future

    out = node_client_script(relay, js_identity, """
        const msgs = await tg.inbox();
        process.stdout.write(JSON.stringify(msgs.map((m) => ({
          text: m.text, expiresAt: m.expiresAt, expired: m.expired,
        }))));
    """)
    assert len(out) == 1
    assert out[0]["expiresAt"] == future
    assert out[0]["expired"] is False


def test_javascript_sets_expiry_and_python_reads_it(relay):
    py_identity = TelegraphClient.generate_identity()
    py = TelegraphClient(relay, identity=py_identity)
    js_identity = TelegraphClient.generate_identity()
    py.register(handle="py-exp-reader")
    TelegraphClient(relay, identity=js_identity).register(handle="js-exp-sender")

    # JS sends an already-past expiry (1) — Python must flag it expired.
    node_client_script(relay, js_identity, """
        await tg.send('@py-exp-reader', 'stale from js', { expiresAt: 1 });
        process.stdout.write('{}');
    """)
    msgs = py.inbox()
    assert len(msgs) == 1
    assert msgs[0].text == "stale from js"
    assert msgs[0].expires_at == 1
    assert msgs[0].expired is True


def test_python_drop_expired_filters_and_acks(relay):
    a = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    b = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    a.register(handle="py-exp-a")
    b.register(handle="py-exp-b")
    a.send("@py-exp-b", "stale", expires_at=1)  # already past
    # Default: returned, flagged expired.
    seen = b.inbox()
    assert len(seen) == 1 and seen[0].expired is True
    # drop_expired filters the view; ack clears it from the mailbox.
    assert b.inbox(ack=True, drop_expired=True) == []
    assert b.inbox() == []


def test_python_threading_round_trip_and_reply(relay):
    a = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    b = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    a.register(handle="py-th-a")
    b.register(handle="py-th-b")

    opened = a.send("@py-th-b", "ping", thread_id="chat")
    got = b.inbox(ack=True)
    assert got[0].thread_id == "chat"
    replied = b.reply(got[0], "pong")
    assert replied["threadId"] == "chat"
    assert replied["replyTo"] == opened["id"]
    back = a.inbox(ack=True)
    assert back[0].text == "pong"
    assert back[0].reply_to == opened["id"]


def test_threading_to_an_opted_out_recipient_is_dropped_to_plain(relay):
    a = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    b = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    a.register(handle="py-drop-a")
    b.register(handle="py-drop-b", threading=False)  # simulates an old peer

    sent = a.send("@py-drop-b", "plain please", thread_id="nope", priority="high")
    assert sent["threadingApplied"] is False
    assert "threadingDropped" in sent

    msgs = b.inbox(ack=True)
    assert msgs[0].text == "plain please"   # a clean plain message, not raw JSON
    assert msgs[0].thread_id is None
    assert msgs[0].verified is True


def test_signed_endpoints_all_work_from_python(relay):
    """Every signed route, because each one signs a different path and body."""
    tg = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    other = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    tg.register(handle="py-signed")
    other.register(handle="py-other")

    assert isinstance(tg.credits(), dict)         # GET, empty body hash
    assert isinstance(tg.pricing(), dict)         # unsigned
    assert tg.blocks() == []                      # GET signed

    tg.send("@py-other", "a wire to have some sent history")
    assert len(tg.sent()) == 1                    # GET signed
    assert tg.sent()[0]["text"] == "a wire to have some sent history"

    # POST signed, with a body — the hash has to be over the bytes we actually
    # transmitted, not over a re-serialization of the same object.
    tg.block("@py-other", note="testing")
    assert len(tg.blocks()) == 1
    tg.unblock("@py-other")
    assert tg.blocks() == []

    # ack: POST signed with an array body
    msgs = other.inbox()
    assert len(msgs) == 1
    other.ack([m.id for m in msgs])
    assert other.inbox() == []


def test_ack_clears_the_mailbox_and_inbox_ack_shorthand_works(relay):
    a = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    b = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    a.register(handle="py-acka")
    b.register(handle="py-ackb")

    a.send("@py-ackb", "read and acked in one call")
    msgs = b.inbox(ack=True)
    assert len(msgs) == 1
    assert b.inbox() == [], "ack=True should have cleared the mailbox"


def test_idempotency_key_collapses_a_retry_to_one_delivery(relay):
    a = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    b = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    a.register(handle="py-idema")
    b.register(handle="py-idemb")

    first = a.send("@py-idemb", "charge me once", idempotency_key="inv-9")
    assert first["idempotent"] is False
    assert first["duplicate"] is False
    used_after_first = a.credits()["freeUsedToday"]

    # A retry under the same key returns the original id, delivers nothing new,
    # and does not charge a second time.
    retry = a.send("@py-idemb", "charge me once", idempotency_key="inv-9")
    assert retry["idempotent"] is True
    assert retry["id"] == first["id"]
    assert a.credits()["freeUsedToday"] == used_after_first, "a keyed retry must not re-charge"

    # Only one wire actually landed.
    assert len(b.inbox()) == 1

    # An over-long key is rejected client-side before any request.
    with pytest.raises(ValueError):
        a.send("@py-idemb", "hi", idempotency_key="x" * 129)


def test_delivery_receipts_prove_a_wire_was_fetched(relay):
    a = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    b = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    a.register(handle="py-rcpta")
    b.register(handle="py-rcptb")

    sent = a.send("@py-rcptb", "did it land?")
    assert a.receipts() == [], "no receipt until the recipient acks with one"

    # Bob fetches and acks, signing a delivery receipt per wire.
    got = b.inbox(ack=True, receipt=True)
    assert len(got) == 1

    receipts = a.receipts()
    assert len(receipts) == 1
    assert receipts[0]["messageId"] == sent["id"]
    assert receipts[0]["recipient"] == b.identity["address"]
    assert receipts[0]["recipientHandle"] == "py-rcptb"
    assert receipts[0]["verified"] is True


def test_blocking_from_python_actually_stops_a_wire(relay):
    victim = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    spammer = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    victim.register(handle="py-victim")
    spammer.register(handle="py-spammer")

    spammer.send("@py-victim", "before the block")
    victim.block("@py-spammer")

    with pytest.raises(TelegraphError) as err:
        spammer.send("@py-victim", "after the block")
    assert err.value.status == 403
    assert err.value.data["error"] == "recipient_blocked_sender"

    # The blocked wire was never stored: only the pre-block one is there.
    assert len(victim.inbox()) == 1


def test_long_poll_returns_the_instant_a_wire_lands(relay):
    import threading

    a = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    b = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    a.register(handle="py-lpa")
    b.register(handle="py-lpb")

    # Park on an empty mailbox with a 20s hold, then send after a beat. If
    # long-poll works, this returns in well under a second — not in 20.
    def send_soon():
        time.sleep(1.0)
        a.send("@py-lpb", "woke you up")

    threading.Thread(target=send_soon, daemon=True).start()
    started = time.time()
    msgs = b.inbox(wait=20)
    elapsed = time.time() - started

    assert len(msgs) == 1
    assert msgs[0].text == "woke you up"
    assert elapsed < 10, f"long-poll took {elapsed:.1f}s — it looks like it polled rather than woke"


def test_long_poll_timing_out_is_empty_not_an_error(relay):
    b = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    b.register(handle="py-lp-timeout")
    started = time.time()
    assert b.inbox(wait=2) == []          # nothing arrives; must not raise
    assert time.time() - started >= 1.5   # and it really did hold the connection


def test_a_relay_error_is_a_typed_exception_not_a_crash(relay):
    tg = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    with pytest.raises(TelegraphError) as err:
        tg.lookup("@nobody-is-called-this")
    assert err.value.status == 404
    assert err.value.data.get("error")

    # Sending to someone who doesn't exist fails before any encryption happens.
    tg.register(handle="py-errors")
    with pytest.raises(TelegraphError):
        tg.send("@still-nobody", "into the void")

    # And the SDK rejects a nonsense wire without troubling the relay at all.
    with pytest.raises(ValueError):
        tg.send("@py-errors", "")
    with pytest.raises(ValueError):
        tg.send("@py-errors", "x" * 4001)


def test_an_identity_round_trips_through_a_file(relay, tmp_path):
    path = tmp_path / "id.json"
    tg = TelegraphClient(relay, identity=TelegraphClient.generate_identity())
    tg.register(handle="py-persist")
    TelegraphClient.save_identity(tg.identity, str(path))

    # A fresh process, loading the key off disk, is the same agent.
    reloaded = TelegraphClient(relay, identity=TelegraphClient.load_identity(str(path)))
    assert reloaded.identity["address"] == tg.identity["address"]
    assert isinstance(reloaded.credits(), dict), "the reloaded identity can still sign"
