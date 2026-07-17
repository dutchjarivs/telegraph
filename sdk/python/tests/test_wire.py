"""Wire-envelope pack/unpack — pure, no relay. The cross-language bytes matter:
these must match what the JavaScript SDK produces so a threaded wire packed by
one unpacks in the other (see test_e2e.py for the live interop check)."""
import pytest

from telegraph import pack_wire, unpack_wire, group_threads, MAX_ATTACHMENTS
from telegraph.client import _decode_attachments


def test_pack_stays_bare_without_metadata():
    assert pack_wire("hello") == "hello"
    # A message that merely looks like JSON is sent verbatim.
    assert pack_wire('{"a":1}') == '{"a":1}'


def test_pack_produces_the_exact_marked_envelope_bytes():
    # Compact JSON, key order _tgv, text, then metadata — byte-identical to the
    # JavaScript SDK's JSON.stringify({_tgv:1, text, ...}).
    assert pack_wire("hi", thread_id="T", reply_to="M", priority="high") == \
        '{"_tgv":1,"text":"hi","threadId":"T","replyTo":"M","priority":"high"}'


def test_pack_rejects_bad_priority():
    with pytest.raises(ValueError):
        pack_wire("hi", priority="urgent")


def test_unpack_round_trips_and_reads_bare_as_text():
    packed = pack_wire("yo", thread_id="T", reply_to="R", priority="low")
    assert unpack_wire(packed) == {"text": "yo", "threadId": "T", "replyTo": "R", "priority": "low", "attachments": []}
    assert unpack_wire("just text") == {"text": "just text", "threadId": None, "replyTo": None, "priority": None, "attachments": []}


def test_unpack_never_mistakes_ordinary_json_for_an_envelope():
    literal = '{"v":1,"text":"my actual message"}'  # no _tgv marker
    assert unpack_wire(literal)["text"] == literal
    assert unpack_wire("{not json")["text"] == "{not json"
    assert unpack_wire('{"_tgv":1}')["text"] == '{"_tgv":1}'  # marker but no string text


def test_unpack_drops_a_bad_priority_to_none():
    assert unpack_wire('{"_tgv":1,"text":"x","priority":"nonsense"}')["priority"] is None


def test_pack_embeds_attachments_with_js_matching_key_order():
    # name, mime, size, data — the same key order the JS SDK's wire.js emits, so
    # a packed attachment envelope is byte-identical across the two SDKs.
    packed = pack_wire("see file", attachments=[{"name": "a.txt", "mime": "text/plain", "size": 3, "data": "AAEC"}])
    assert packed == \
        '{"_tgv":1,"text":"see file","attachments":[{"name":"a.txt","mime":"text/plain","size":3,"data":"AAEC"}]}'


def test_pack_defaults_attachment_name_and_mime():
    env = unpack_wire(pack_wire("", attachments=[{"data": "AAEC"}]))
    assert env["attachments"][0]["name"] == "attachment-1"
    assert env["attachments"][0]["mime"] == "application/octet-stream"


def test_empty_attachments_list_stays_bare():
    assert pack_wire("hi", attachments=[]) == "hi"


def test_pack_rejects_too_many_attachments():
    with pytest.raises(ValueError):
        pack_wire("x", attachments=[{"data": "AA"}] * (MAX_ATTACHMENTS + 1))


def test_unpack_skips_malformed_attachment_entries():
    env = unpack_wire('{"_tgv":1,"text":"t","attachments":[{"data":"AAEC"},{"name":"no-data"},42,null]}')
    assert len(env["attachments"]) == 1
    assert env["attachments"][0]["data"] == "AAEC"


def test_decode_attachments_survives_hostile_base64():
    # A sender controls the envelope, so a crafted wire can carry malformed
    # base64 in `data`. This runs inside inbox(); an unguarded b64decode raise
    # would blow up the whole mailbox read from one bad wire. It must not throw —
    # the corrupt attachment comes back with empty bytes, name/mime preserved.
    env = unpack_wire('{"_tgv":1,"text":"hi","attachments":[{"name":"bad.bin","mime":"x/y","size":9,"data":"!!!not base64!!!"}]}')
    decoded = _decode_attachments(env["attachments"])
    assert decoded[0]["name"] == "bad.bin"
    assert decoded[0]["data"] == b""  # corrupt → empty bytes, not an exception


def test_decode_attachments_round_trips_valid_base64():
    env = unpack_wire('{"_tgv":1,"text":"hi","attachments":[{"name":"a","mime":"x/y","size":3,"data":"AAEC"}]}')
    assert _decode_attachments(env["attachments"])[0]["data"] == bytes([0, 1, 2])


def test_group_threads_buckets_by_thread_oldest_first():
    wires = [
        {"id": "m1", "ts": 100, "threadId": "A"},
        {"id": "m2", "ts": 300, "threadId": "B"},
        {"id": "m3", "ts": 200, "threadId": "A"},
        {"id": "m4", "ts": 50, "threadId": None},
    ]
    grouped = group_threads(wires)
    a = next(t for t in grouped if t["threadId"] == "A")
    assert [w["id"] for w in a["wires"]] == ["m1", "m3"]
    assert any(t["threadId"] == "m4" for t in grouped)  # lone wire keyed by its id
    assert grouped[0]["threadId"] == "B"  # most-recently-active first


def test_client_tolerates_a_malformed_relay_response(monkeypatch):
    # A semi-trusted relay returning a non-list where a list is expected must not
    # crash the client (Python would otherwise iterate a string char-by-char into
    # an AttributeError). inbox/sent/directory should come back empty.
    from telegraph import TelegraphClient
    c = TelegraphClient(identity=TelegraphClient.generate_identity())
    monkeypatch.setattr(c, "_req", lambda *a, **k: {"messages": "nope", "agents": {"x": 1}, "count": 0})
    assert c.inbox() == []
    assert c.sent() == []
    assert c.directory("x")["agents"] == []
