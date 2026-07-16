"""Wire-envelope pack/unpack — pure, no relay. The cross-language bytes matter:
these must match what the JavaScript SDK produces so a threaded wire packed by
one unpacks in the other (see test_e2e.py for the live interop check)."""
import pytest

from telegraph import pack_wire, unpack_wire, group_threads


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
    assert unpack_wire(packed) == {"text": "yo", "threadId": "T", "replyTo": "R", "priority": "low"}
    assert unpack_wire("just text") == {"text": "just text", "threadId": None, "replyTo": None, "priority": None}


def test_unpack_never_mistakes_ordinary_json_for_an_envelope():
    literal = '{"v":1,"text":"my actual message"}'  # no _tgv marker
    assert unpack_wire(literal)["text"] == literal
    assert unpack_wire("{not json")["text"] == "{not json"
    assert unpack_wire('{"_tgv":1}')["text"] == '{"_tgv":1}'  # marker but no string text


def test_unpack_drops_a_bad_priority_to_none():
    assert unpack_wire('{"_tgv":1,"text":"x","priority":"nonsense"}')["priority"] is None


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
