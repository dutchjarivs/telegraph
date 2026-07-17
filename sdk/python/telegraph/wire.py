"""Wire envelope — threading metadata carried *inside* the sealed box.

The relay never sees this: a wire's plaintext is end-to-end encrypted, so a
thread id, a reply-to, or a priority packed here is invisible to the relay and
needs no relay change. It is a convention between clients, and it interoperates
byte-for-byte with the JavaScript SDK's ``wire.js`` (same ``_tgv`` marker, same
compact JSON), so a Python agent and a JS agent can thread a conversation.

Two plaintext forms travel over the wire, chosen for backward compatibility:

* a bare string ....................... a plain message (what 0.1.0 produced).
* a JSON object with ``"_tgv": 1`` .... a structured wire: ``text`` plus optional
                                        ``threadId`` / ``replyTo`` / ``priority``.

A sender only produces the structured form for a recipient advertising
``WIRE_ENVELOPE_CAPABILITY`` (so an older peer never receives JSON it can't
read), and :func:`unpack_wire` only treats a plaintext as structured when it
carries the exact marker *and* a string ``text`` — so a message that merely
looks like JSON is never rewritten.
"""
from __future__ import annotations

import json
from typing import Any

WIRE_ENVELOPE_VERSION = 1
WIRE_ENVELOPE_CAPABILITY = "wire-envelope-v1"
PRIORITIES = ("low", "normal", "high")

# Attachments ride inside the same sealed box as the text (see the JS wire.js).
# They live in the structured envelope as ``attachments: [{name, mime, size,
# data}]`` where ``data`` is the bytes already base64-encoded — wire.py stays
# free of any binary/base64 step so it byte-matches the JS SDK. A separate
# capability gates them: parsing an envelope's text does not imply knowing how
# to surface its files.
ATTACHMENTS_CAPABILITY = "attachments-v1"
MAX_ATTACHMENTS = 16
MAX_ATTACHMENT_NAME = 256


def _normalize_attachment(a: Any, i: int) -> dict:
    """One caller attachment → on-wire shape. Key order ``name, mime, size,
    data`` matches the JS SDK so packed envelopes are byte-identical."""
    if not isinstance(a, dict):
        raise TypeError(f"pack_wire: attachment {i} must be a dict")
    data = a.get("data")
    if not isinstance(data, str):
        raise TypeError(f"pack_wire: attachment {i} data must be a base64 string")
    name = a.get("name")
    name = f"attachment-{i + 1}" if name is None else str(name)[:MAX_ATTACHMENT_NAME]
    mime = a.get("mime")
    mime = "application/octet-stream" if mime is None else str(mime)[:MAX_ATTACHMENT_NAME]
    size = a.get("size")
    size = size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else 0
    return {"name": name, "mime": mime, "size": size, "data": data}


def pack_wire(text: str, *, thread_id: str | None = None, reply_to: str | None = None,
              priority: str | None = None, attachments: list | None = None) -> str:
    """Pack a message + optional threading metadata and/or attachments into the
    plaintext to seal.

    With no metadata it returns the bare string unchanged (the common case:
    zero overhead, no ambiguity). Compact JSON, key order ``_tgv, text, …`` to
    match the JavaScript SDK exactly.
    """
    if not isinstance(text, str):
        raise TypeError("pack_wire: text must be a string")
    env: dict[str, Any] = {}
    if thread_id is not None:
        env["threadId"] = str(thread_id)
    if reply_to is not None:
        env["replyTo"] = str(reply_to)
    if priority is not None:
        if priority not in PRIORITIES:
            raise ValueError(f"pack_wire: priority must be one of {'|'.join(PRIORITIES)}")
        env["priority"] = priority
    if attachments is not None:
        if not isinstance(attachments, list):
            raise TypeError("pack_wire: attachments must be a list")
        if len(attachments) > MAX_ATTACHMENTS:
            raise ValueError(f"pack_wire: at most {MAX_ATTACHMENTS} attachments per wire")
        if attachments:
            env["attachments"] = [_normalize_attachment(a, i) for i, a in enumerate(attachments)]
    if not env:
        return text
    obj = {"_tgv": WIRE_ENVELOPE_VERSION, "text": text, **env}
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))


def _parse_attachments(raw: Any) -> list[dict]:
    """Read an envelope's attachment list defensively: skip any entry that isn't
    a well-formed ``{data: base64-str}`` descriptor, and cap the count."""
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for a in raw:
        if len(out) >= MAX_ATTACHMENTS:
            break
        if not isinstance(a, dict) or not isinstance(a.get("data"), str):
            continue
        name = a.get("name")
        mime = a.get("mime")
        size = a.get("size")
        out.append({
            "name": name[:MAX_ATTACHMENT_NAME] if isinstance(name, str) else f"attachment-{len(out) + 1}",
            "mime": mime[:MAX_ATTACHMENT_NAME] if isinstance(mime, str) else "application/octet-stream",
            "size": size if isinstance(size, int) and not isinstance(size, bool) and size >= 0 else 0,
            "data": a["data"],
        })
    return out


def unpack_wire(plaintext: str) -> dict:
    """Parse a decrypted plaintext into ``{text, threadId, replyTo, priority,
    attachments}``.

    Defensive: only a JSON object carrying the exact ``_tgv`` marker and a string
    ``text`` is read as an envelope; everything else comes back with the whole
    plaintext as ``text`` and ``None`` metadata (the 0.1.0 reading). Attachment
    ``data`` comes back still base64 (the client decodes it for the caller).
    """
    bare = {"text": plaintext, "threadId": None, "replyTo": None, "priority": None, "attachments": []}
    if not isinstance(plaintext, str) or not plaintext or plaintext[0] != "{":
        return bare
    try:
        obj = json.loads(plaintext)
    except (ValueError, TypeError):
        return bare
    if not isinstance(obj, dict) or obj.get("_tgv") != WIRE_ENVELOPE_VERSION or not isinstance(obj.get("text"), str):
        return bare
    priority = obj.get("priority")
    return {
        "text": obj["text"],
        "threadId": obj["threadId"] if isinstance(obj.get("threadId"), str) else None,
        "replyTo": obj["replyTo"] if isinstance(obj.get("replyTo"), str) else None,
        "priority": priority if priority in PRIORITIES else None,
        "attachments": _parse_attachments(obj.get("attachments")),
    }


def group_threads(messages) -> list[dict]:
    """Group wires into conversations by ``thread_id`` (or own id), client-side.

    Returns ``[{"threadId": ..., "wires": [...]}]``, most-recently-active first,
    with wires oldest-first inside each thread. Accepts Message objects or dicts.
    """
    def field(m, name):
        return getattr(m, name, None) if not isinstance(m, dict) else m.get(name)

    threads: dict[str, list] = {}
    for m in messages or []:
        key = field(m, "thread_id") or field(m, "threadId") or field(m, "id")
        threads.setdefault(key, []).append(m)
    out = []
    for tid, wires in threads.items():
        wires.sort(key=lambda m: field(m, "ts") or 0)
        out.append({"threadId": tid, "wires": wires})
    out.sort(key=lambda t: (field(t["wires"][-1], "ts") or 0), reverse=True)
    return out
