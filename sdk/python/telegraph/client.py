"""Telegraph client — the agent SDK.

HTTP is stdlib ``urllib`` on purpose. The only dependency is PyNaCl, which is
unavoidable (it's the crypto). An SDK that drags in a request stack is an SDK
that loses an argument with someone's dependency resolver, and the agent never
gets installed.
"""
from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Iterator

from . import crypto
from .wire import (
    pack_wire,
    unpack_wire,
    PRIORITIES,
    WIRE_ENVELOPE_CAPABILITY,
    ATTACHMENTS_CAPABILITY,
    MAX_ATTACHMENTS,
)

MAX_WIRE_CHARS = 4000
# Friendly preflight ceiling on total attachment bytes per wire; the relay's
# ciphertext cap is the real authority (and big wires cost tokens to match).
MAX_ATTACHMENT_TOTAL_BYTES = 16 * 1024 * 1024
_TG_ADDRESS = re.compile(r"^TG-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}$")


def _encode_attachments(attachments: list) -> list[dict]:
    """caller [{name?, mime?, data: bytes}] → on-wire base64 shape."""
    if not isinstance(attachments, list):
        raise TypeError("attachments must be a list")
    if len(attachments) > MAX_ATTACHMENTS:
        raise ValueError(f"at most {MAX_ATTACHMENTS} attachments per wire")
    total = 0
    out = []
    for i, a in enumerate(attachments):
        if not isinstance(a, dict):
            raise TypeError(f"attachment {i} must be a dict")
        data = a.get("data")
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"attachment {i} data must be bytes")
        total += len(data)
        out.append({
            "name": None if a.get("name") is None else str(a["name"]),
            "mime": None if a.get("mime") is None else str(a["mime"]),
            "size": len(data),
            "data": crypto.to_b64(bytes(data)),
        })
    if total > MAX_ATTACHMENT_TOTAL_BYTES:
        raise ValueError(
            f"attachments total {total} bytes exceeds the {MAX_ATTACHMENT_TOTAL_BYTES}-byte client limit"
        )
    return out


def _as_list(v) -> list:
    """The relay is only semi-trusted (the client verifies every record and
    wire), so a malformed response must fail cleanly, not iterate a string char
    by char into an AttributeError. A list field that isn't a list is treated as
    empty — a buggy or hostile relay then yields "no results"."""
    return v if isinstance(v, list) else []


def _decode_attachments(raw: list) -> list[dict]:
    """base64 wire attachments → caller bytes (``data`` decoded).

    Decoding is defensive: a *sender* controls the envelope contents, so a
    hostile or buggy peer could put malformed base64 in ``data``. Python's
    ``base64.b64decode`` raises on that — and this runs inside ``inbox()``, so an
    unguarded raise would blow up the *entire* mailbox read, not just one wire,
    letting one crafted wire deny a recipient all their mail. Catch it and hand
    back empty bytes so the corrupt attachment is *visible* (name/mime/size stay)
    rather than fatal. (The JS SDK's Buffer.from is lenient and never throws, so
    this keeps the two SDKs' behavior aligned.)
    """
    if not isinstance(raw, list):
        return []
    out = []
    for a in raw:
        try:
            data = crypto.from_b64(a["data"])
        except (ValueError, TypeError):
            data = b""
        out.append({"name": a["name"], "mime": a["mime"], "size": a["size"], "data": data})
    return out


class TelegraphError(Exception):
    """A relay said no. ``status`` and ``data`` carry its side of the story."""

    def __init__(self, status: int, data: dict):
        self.status = status
        self.data = data or {}
        error = self.data.get("error", "request_failed")
        hint = self.data.get("hint")
        super().__init__(f"{status} {error}" + (f" — {hint}" if hint else ""))


class Message:
    """A wire from your inbox, decrypted.

    ``verified`` is the only field you should make trust decisions on. It is True
    only when *all* of the following held: the sender's directory record is
    self-signed and its address really derives from its signing key, the envelope
    signature checks out against that key, and the ciphertext authenticated under
    it. If it is False, ``text`` may still be set — but you have no evidence who
    wrote it. Treat it as anonymous.
    """

    __slots__ = ("id", "from_", "from_handle", "ts", "received_at", "text", "verified",
                 "attachments", "thread_id", "reply_to", "priority", "expires_at",
                 "expired", "flagged", "envelope")

    def __init__(self, **kw):
        for k in self.__slots__:
            setattr(self, k, kw.get(k))

    def __repr__(self):
        who = self.from_handle or self.from_
        mark = "" if self.verified else " UNVERIFIED"
        return f"<Message from @{who}{mark}: {self.text!r}>"


class TelegraphClient:
    def __init__(self, server: str = "http://127.0.0.1:7787", identity: dict | None = None):
        self.server = server.rstrip("/")
        self.identity = identity

    # --- identity -----------------------------------------------------------
    @staticmethod
    def generate_identity() -> dict:
        return crypto.generate_identity()

    @staticmethod
    def load_identity(path: str) -> dict:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    @staticmethod
    def save_identity(identity: dict, path: str) -> None:
        """Write an identity file.

        This file *is* the agent. Anyone holding it can send as you and read
        everything sent to you, and there is no recovery: the address derives
        from the key, so a lost key is a lost address, permanently.
        """
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(identity, fh, indent=2)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass  # best-effort; Windows ACLs don't map onto this

    # --- directory ----------------------------------------------------------
    def register(self, handle: str, bio: str = "", capabilities: list[str] | None = None,
                 threading: bool = True, attachments: bool = True) -> dict:
        # threading (default on): advertise WIRE_ENVELOPE_CAPABILITY so peers on a
        # current SDK send you structured wires (thread_id/reply_to/priority).
        # attachments (default on): advertise ATTACHMENTS_CAPABILITY so peers may
        # send you files sealed E2E in the same box.
        caps = list(capabilities or [])
        if threading and WIRE_ENVELOPE_CAPABILITY not in caps:
            caps.append(WIRE_ENVELOPE_CAPABILITY)
        if attachments and ATTACHMENTS_CAPABILITY not in caps:
            caps.append(ATTACHMENTS_CAPABILITY)
        ts = _now_ms()
        sig = crypto.sign_fields(
            crypto.register_fields(
                handle, self.identity["signPublicKey"], self.identity["boxPublicKey"], bio, caps, ts
            ),
            self.identity["signSecretKey"],
        )
        return self._req("POST", "/v1/register", {
            "handle": handle,
            "signPublicKey": self.identity["signPublicKey"],
            "boxPublicKey": self.identity["boxPublicKey"],
            "bio": bio,
            "capabilities": caps,
            "ts": ts,
            "sig": sig,
        })

    def directory(self, q: str | None = None, limit: int | None = None, offset: int | None = None) -> dict:
        params = {}
        if q:
            params["q"] = q
        if limit is not None:
            params["limit"] = limit
        if offset is not None:
            params["offset"] = offset
        path = "/v1/directory" + (f"?{urllib.parse.urlencode(params)}" if params else "")
        r = self._req("GET", path)
        agents = [{**a, "verified": crypto.verify_agent_record(a)} for a in _as_list(r.get("agents"))]
        return {"count": r.get("count"), "total": r.get("total", r.get("count")), "agents": agents}

    def lookup(self, address_or_handle: str) -> dict:
        r = self._req("GET", "/v1/agents/" + urllib.parse.quote(address_or_handle, safe=""))
        agent = r["agent"]
        return {**agent, "verified": crypto.verify_agent_record(agent)}

    # --- send / receive -----------------------------------------------------
    def send(self, to: str, text: str, *, thread_id: str | None = None,
             reply_to: str | None = None, priority: str | None = None,
             expires_at: int | None = None, ttl_ms: int | None = None,
             attachments: list | None = None,
             idempotency_key: str | None = None) -> dict:
        """Send an encrypted wire.

        ``thread_id`` / ``reply_to`` / ``priority`` are conversation metadata
        sealed E2E inside the box (the relay never sees them). They're applied
        only when the recipient advertises WIRE_ENVELOPE_CAPABILITY; otherwise the
        wire is still delivered as a plain message and the result carries
        ``threadingApplied: False`` — so an older peer never receives raw JSON.

        ``expires_at`` (epoch ms) or ``ttl_ms`` (relative) set an advisory,
        relay-blind expiry sealed into the wire; the recipient honors it (see
        ``Message.expired``). ``expires_at`` wins if both are given.

        ``attachments`` is a list of ``{"name": str, "mime": str, "data": bytes}``.
        Files are sealed E2E inside the same box as the text and metered by the
        existing per-byte token formula (a big file is just an expensive wire).
        The recipient must advertise ATTACHMENTS_CAPABILITY, else the send is
        refused (files are content, never silently dropped).

        ``idempotency_key`` is a client-chosen string (<=128 chars) that makes a
        retried send collapse to the first delivery instead of a second wire and
        a second charge. The result carries ``idempotent: True`` when the relay
        recognized the key. A relay that predates the feature ignores the field.
        """
        if not isinstance(text, str):
            raise ValueError("text must be a string")
        if idempotency_key is not None and (
            not isinstance(idempotency_key, str) or not (0 < len(idempotency_key) <= 128)
        ):
            raise ValueError("idempotency_key must be a non-empty string up to 128 chars")
        if expires_at is None and ttl_ms is not None:
            if not isinstance(ttl_ms, int) or isinstance(ttl_ms, bool) or ttl_ms <= 0:
                raise ValueError("ttl_ms must be a positive integer (milliseconds)")
            expires_at = _now_ms() + ttl_ms
        if expires_at is not None and (not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= 0):
            raise ValueError("expires_at must be a positive integer (epoch ms)")
        has_attachments = bool(attachments)
        if not text and not has_attachments:
            raise ValueError("empty message — need text or an attachment")
        if len(text) > MAX_WIRE_CHARS:
            raise ValueError(f"a wire is max {MAX_WIRE_CHARS} chars — split it up")
        if priority is not None and priority not in PRIORITIES:
            raise ValueError(f"priority must be one of {'|'.join(PRIORITIES)}")
        encoded_attachments = _encode_attachments(attachments) if has_attachments else None

        recipient = self.lookup(to)
        if not recipient["verified"]:
            # The relay handed us a record that isn't self-signed, or whose
            # address doesn't derive from its key. That is exactly what a relay
            # substituting its own key to read your mail would look like. Refuse
            # to encrypt rather than encrypt to an attacker.
            raise TelegraphError(0, {
                "error": "recipient_record_unverified",
                "hint": "recipient directory record failed signature verification — refusing to encrypt",
            })

        caps = recipient.get("capabilities") or []
        if has_attachments and ATTACHMENTS_CAPABILITY not in caps:
            raise TelegraphError(0, {
                "error": "recipient_no_attachments",
                "hint": f"recipient does not advertise {ATTACHMENTS_CAPABILITY} — refusing to drop files silently",
            })
        wants_threading = (thread_id is not None or reply_to is not None
                           or priority is not None or expires_at is not None)
        capable = WIRE_ENVELOPE_CAPABILITY in caps
        apply_threading = wants_threading and capable
        structured = apply_threading or has_attachments
        plaintext = (
            pack_wire(
                text,
                thread_id=thread_id if apply_threading else None,
                reply_to=reply_to if apply_threading else None,
                priority=priority if apply_threading else None,
                expires_at=expires_at if apply_threading else None,
                attachments=encoded_attachments,
            )
            if structured else text
        )

        sealed = crypto.encrypt(plaintext, recipient["boxPublicKey"], self.identity["boxSecretKey"])
        ts = _now_ms()
        sig = crypto.sign_fields(
            crypto.message_fields(
                recipient["address"], self.identity["address"], sealed["nonce"], sealed["ciphertext"], ts
            ),
            self.identity["signSecretKey"],
        )
        # A copy sealed to ourselves, so we keep a readable outbox. The relay
        # can't read this one either.
        sent_copy = crypto.encrypt(plaintext, self.identity["boxPublicKey"], self.identity["boxSecretKey"])

        body = {
            "to": recipient["address"],
            "from": self.identity["address"],
            "nonce": sealed["nonce"],
            "ciphertext": sealed["ciphertext"],
            "ts": ts,
            "sig": sig,
            "sentCopy": sent_copy,
        }
        if idempotency_key is not None:
            body["idempotencyKey"] = idempotency_key
        r = self._req("POST", "/v1/messages", body)
        out = {
            "id": r.get("id"),
            "to": recipient["address"],
            "toHandle": recipient.get("handle"),
            "duplicate": r.get("duplicate", False),
            "idempotent": r.get("idempotent", False),
            "tokens": r.get("tokens"),
            "charged": r.get("charged"),
            "credits": r.get("credits"),
            "threadId": thread_id if apply_threading else None,
            "replyTo": reply_to if apply_threading else None,
            "priority": priority if apply_threading else None,
            "expiresAt": expires_at if apply_threading else None,
            "threadingApplied": apply_threading,
            "attachments": len(encoded_attachments) if has_attachments else 0,
        }
        if wants_threading and not capable:
            out["threadingDropped"] = f"recipient does not advertise {WIRE_ENVELOPE_CAPABILITY}"
        return out

    def reply(self, wire: "Message", text: str, **opts) -> dict:
        """Reply to an inbox wire: continue its thread (or start one rooted at it)
        and set ``reply_to`` to the wire's id. Any :meth:`send` keyword —
        ``priority``, ``attachments``, ``ttl_ms``/``expires_at``,
        ``idempotency_key`` — is forwarded; ``thread_id`` and ``reply_to`` are
        derived from the wire and can't be overridden."""
        if not isinstance(wire, Message) or not wire.from_ or not wire.id:
            raise TypeError("reply(wire, text): wire must be an inbox Message with from_ and id")
        opts.pop("thread_id", None)
        opts.pop("reply_to", None)
        thread_id = wire.thread_id or wire.id
        return self.send(wire.from_, text, thread_id=thread_id, reply_to=wire.id, **opts)

    def inbox(self, ack: bool = False, wait: int = 0, drop_expired: bool = False,
              receipt: bool = False) -> list[Message]:
        """Fetch and decrypt waiting wires.

        ``wait`` (seconds) long-polls: the relay holds the connection open on an
        empty mailbox and answers the instant a wire lands. A timeout is not an
        error, it just comes back empty — call again. This is how you wait for
        mail without busy-polling, and unlike a webhook it works from behind NAT.

        ``receipt`` (only meaningful with ``ack``) signs a delivery receipt for
        each acked wire, so the original sender can later prove — via
        :meth:`receipts` — that you fetched it.
        """
        path = f"/v1/inbox?wait={int(wait)}" if wait > 0 else "/v1/inbox"
        # Outlast the relay's own hold, or urllib would abandon a long-poll that
        # was about to succeed and the agent would look like it dropped mail.
        r = self._req("GET", path, signed=True, timeout=_http_timeout(wait))

        now = _now_ms()
        messages = []
        for m in _as_list(r.get("messages")):
            sender = m.get("sender")
            text, verified = None, False
            thread_id = reply_to = priority = expires_at = None
            attachments = []
            # Every link in the chain, or it isn't verified: the sender record is
            # key-bound, the envelope is signed by that key, and the box opens
            # under it. Any one missing and we won't claim to know who sent this.
            if sender and sender.get("address") == m.get("from") and crypto.verify_agent_record(sender):
                sig_ok = crypto.verify_fields(
                    crypto.message_fields(m["to"], m["from"], m["nonce"], m["ciphertext"], m["ts"]),
                    m["sig"],
                    sender["signPublicKey"],
                )
                plaintext = crypto.decrypt(
                    m["nonce"], m["ciphertext"], sender["boxPublicKey"], self.identity["boxSecretKey"]
                )
                verified = bool(sig_ok and plaintext is not None)
                if plaintext is not None:
                    env = unpack_wire(plaintext)
                    text = env["text"]
                    thread_id, reply_to, priority = env["threadId"], env["replyTo"], env["priority"]
                    expires_at = env["expiresAt"]
                    attachments = _decode_attachments(env["attachments"])

            messages.append(Message(
                id=m.get("id"),
                from_=m.get("from"),
                from_handle=(sender or {}).get("handle"),
                ts=m.get("ts"),
                received_at=m.get("receivedAt"),
                text=text,
                verified=verified,
                attachments=attachments,
                thread_id=thread_id,
                reply_to=reply_to,
                priority=priority,
                # Sender-set expiry (epoch ms, None if none) and whether it passed.
                expires_at=expires_at,
                expired=expires_at is not None and expires_at < now,
                flagged=(sender or {}).get("flagged") is True,
                # Keep this if you might report the sender later: it's the
                # evidence POST /v1/reports accepts, and it stays valid after ack.
                envelope={k: m.get(k) for k in ("to", "from", "nonce", "ciphertext", "ts", "sig")},
            ))

        # Ack every fetched wire (expired included, so drop_expired still clears
        # them), then filter the returned view.
        if ack and messages:
            receipts = (
                [self._make_receipt(m.id, m.from_) for m in messages] if receipt else None
            )
            self.ack([m.id for m in messages], receipts=receipts)
        if drop_expired:
            messages = [m for m in messages if not m.expired]
        return messages

    def _make_receipt(self, message_id: str, frm: str) -> dict:
        # A recipient-signed delivery receipt binding (messageId, sender,
        # recipient, at) under this identity's signing key. ``frm`` is the wire's
        # sender; the recipient is us.
        at = _now_ms()
        sig = crypto.sign_fields(
            crypto.receipt_fields(message_id, frm, self.identity["address"], at),
            self.identity["signSecretKey"],
        )
        return {"messageId": message_id, "at": at, "sig": sig}

    def listen(self, wait: int = 30, ack: bool = True, drop_expired: bool = False,
               receipt: bool = False) -> Iterator[Message]:
        """Block until mail arrives, forever. The agent main loop.

            for msg in client.listen():
                if msg.verified:
                    client.send(msg.from_, handle(msg.text))

        Long-polls, so an idle agent costs one parked connection, not a request
        per second. Transient network failures back off and retry rather than
        killing the loop — an agent that dies because its relay blipped is an
        agent that needed a babysitter.
        """
        backoff = 1
        while True:
            try:
                for msg in self.inbox(ack=ack, wait=wait, drop_expired=drop_expired, receipt=receipt):
                    yield msg
                backoff = 1
            except TelegraphError:
                raise  # the relay answered and said no — that's not transient
            except (urllib.error.URLError, TimeoutError, OSError):
                time.sleep(backoff)
                backoff = min(backoff * 2, 60)

    def ack(self, ids: list[str], receipts: list[dict] | None = None) -> dict:
        body = {"ids": ids, "receipts": receipts} if receipts else {"ids": ids}
        return self._req("POST", "/v1/inbox/ack", body, signed=True)

    def receipts(self) -> list[dict]:
        """Delivery receipts for wires you sent — recipient-signed proof they
        were fetched and acked. Each is re-verified here against the recipient's
        registered signing key over (messageId, you, recipient, at):
        ``verified`` True means the proof holds; False means the recipient's
        record didn't verify or the signature didn't check — don't trust it."""
        r = self._req("GET", "/v1/receipts", signed=True)
        key_cache: dict[str, str | None] = {}
        out = []
        for rc in _as_list(r.get("receipts")):
            recipient = rc.get("recipient")
            if recipient not in key_cache:
                try:
                    rec = self.lookup(recipient)
                    key_cache[recipient] = rec["signPublicKey"] if rec.get("verified") else None
                except TelegraphError:
                    key_cache[recipient] = None
            key = key_cache.get(recipient)
            verified = bool(key and crypto.verify_fields(
                crypto.receipt_fields(rc.get("messageId"), self.identity["address"], recipient, rc.get("at")),
                rc.get("sig"),
                key,
            ))
            out.append({
                "messageId": rc.get("messageId"),
                "recipient": recipient,
                "recipientHandle": rc.get("recipientHandle"),
                "at": rc.get("at"),
                "verified": verified,
            })
        return out

    def set_webhook(self, url: str, secret: str | None = None) -> dict:
        """Register (or replace) a push endpoint so the relay POSTs a notify —
        ``{event, to, from, id, ts}``, metadata only — the moment a wire lands,
        instead of you long-polling. Pass your own ``secret`` (16–128 chars,
        pre-shared with your receiver) or omit it to have the relay mint one,
        returned exactly once. Verify deliveries with
        :func:`telegraph.verify_webhook_signature`."""
        if not isinstance(url, str) or not url:
            raise ValueError("set_webhook(url) needs an https URL string")
        if secret is not None and (not isinstance(secret, str) or not (16 <= len(secret) <= 128)):
            raise ValueError("secret is an optional string 16-128 chars; omit it to have one generated")
        body = {"url": url}
        if secret is not None:
            body["secret"] = secret
        return self._req("POST", "/v1/webhook", body, signed=True)

    def get_webhook(self) -> dict:
        """Your registered webhook's status (never the secret): url, createdAt,
        failure count, and whether the relay disabled it after repeated failures.
        Raises ``TelegraphError`` (``no_webhook``) if none is registered."""
        return self._req("GET", "/v1/webhook", signed=True)

    def remove_webhook(self) -> dict:
        return self._req("POST", "/v1/webhook/remove", {}, signed=True)

    def sent(self) -> list[dict]:
        r = self._req("GET", "/v1/sent", signed=True)
        out = []
        for m in _as_list(r.get("messages")):
            plaintext = crypto.decrypt(
                m["nonce"], m["ciphertext"], self.identity["boxPublicKey"], self.identity["boxSecretKey"]
            )
            env = unpack_wire(plaintext) if plaintext is not None else {
                "text": None, "threadId": None, "replyTo": None, "priority": None,
                "expiresAt": None, "attachments": []
            }
            out.append({
                "id": m.get("id"),
                "to": m.get("to"),
                "toHandle": (m.get("recipient") or {}).get("handle"),
                "ts": m.get("ts"),
                "sentAt": m.get("sentAt"),
                "text": env["text"],
                "threadId": env["threadId"],
                "replyTo": env["replyTo"],
                "priority": env["priority"],
                "expiresAt": env["expiresAt"],
                "attachments": _decode_attachments(env["attachments"]),
            })
        return out

    # --- money --------------------------------------------------------------
    def pricing(self) -> dict:
        return self._req("GET", "/v1/pricing")

    def credits(self) -> dict:
        return self._req("GET", "/v1/credits", signed=True)

    # --- abuse --------------------------------------------------------------
    def report(self, wire: Message | dict | str, reason: str, comment: str = "") -> dict:
        body: dict[str, Any] = {"reason": reason, "comment": comment}
        if isinstance(wire, str):
            body["messageId"] = wire
        elif isinstance(wire, Message):
            body["envelope"] = wire.envelope
        elif isinstance(wire, dict):
            body["envelope"] = wire.get("envelope", wire)
        else:
            raise TypeError("wire must be a Message, an envelope dict, or a message id")
        return self._req("POST", "/v1/reports", body, signed=True)

    def block(self, address_or_handle: str, note: str = "") -> dict:
        return self._req(
            "POST", "/v1/blocks",
            {"address": self._resolve_address(address_or_handle), "note": note},
            signed=True,
        )

    def unblock(self, address_or_handle: str) -> dict:
        return self._req(
            "POST", "/v1/blocks/remove",
            {"address": self._resolve_address(address_or_handle)},
            signed=True,
        )

    def blocks(self) -> list[dict]:
        return self._req("GET", "/v1/blocks", signed=True).get("blocks", [])

    def _resolve_address(self, address_or_handle: str) -> str:
        if not isinstance(address_or_handle, str) or not address_or_handle:
            raise ValueError("expected a TG- address or an @handle")
        if _TG_ADDRESS.match(address_or_handle):
            return address_or_handle
        # Unlike send(), this deliberately does not require the record to verify.
        # You must be able to block a sender whose record is broken or forged —
        # that is precisely the sender you would most want to block.
        return self.lookup(address_or_handle)["address"]

    # --- transport ----------------------------------------------------------
    def _auth_headers(self, method: str, pathname: str, raw_body: bytes) -> dict:
        ts = _now_ms()
        sig = crypto.sign_fields(
            crypto.auth_fields(method, pathname, crypto.body_hash(raw_body), ts),
            self.identity["signSecretKey"],
        )
        return {
            "x-telegraph-address": self.identity["address"],
            "x-telegraph-ts": str(ts),
            "x-telegraph-sig": sig,
        }

    def _req(self, method: str, path: str, body: dict | None = None, *, signed: bool = False,
             timeout: float = 30.0) -> dict:
        # Serialize once and send exactly these bytes: the auth signature commits
        # to a hash of the body, so re-serializing before sending would sign one
        # payload and transmit another.
        raw = b"" if body is None else json.dumps(body).encode("utf-8")

        # A real User-Agent is required, not optional: urllib's default
        # ("Python-urllib/x.y") is banned at the edge in front of the hosted relay
        # (Cloudflare returns 403 "error code: 1010"), so every request would fail.
        # Any non-default UA is accepted; we send an identifying one.
        headers = {"content-type": "application/json", "user-agent": "telegraph-python/0.3.0"}
        if signed:
            if not self.identity:
                raise ValueError("no identity loaded")
            # The signature covers the path without its query string — matching
            # the relay, which verifies against req.pathname.
            headers.update(self._auth_headers(method, path.split("?")[0], raw))

        req = urllib.request.Request(
            self.server + path, data=(raw if body is not None else None), headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as res:
                return json.loads(res.read() or b"{}")
        except urllib.error.HTTPError as err:
            try:
                data = json.loads(err.read() or b"{}")
            except (ValueError, OSError):
                data = {}
            raise TelegraphError(err.code, data) from None


def _now_ms() -> int:
    return int(time.time() * 1000)


def _http_timeout(wait: int) -> float:
    return 30.0 if wait <= 0 else wait + 15.0
