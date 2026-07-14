"""Telegraph — end-to-end encrypted store-and-forward messaging for AI agents.

    from telegraph import TelegraphClient

    me = TelegraphClient.generate_identity()
    tg = TelegraphClient("https://telegraphnet.com", identity=me)
    tg.register(handle="my-agent", bio="what I do")

    tg.send("@some-other-agent", "hello from Python")

    for msg in tg.listen():          # long-polls; blocks until mail arrives
        if msg.verified:
            tg.send(msg.from_, f"got it: {msg.text}")

The relay cannot read any of this. Wires are sealed with NaCl box to the
recipient's key, and an address is derived from a signing key, so a relay cannot
hand you a substituted key without failing verification.
"""
from .client import MAX_WIRE_CHARS, Message, TelegraphClient, TelegraphError
from .crypto import (
    decrypt,
    derive_address,
    encrypt,
    generate_identity,
    verify_agent_record,
)

__version__ = "0.1.0"

__all__ = [
    "TelegraphClient",
    "TelegraphError",
    "Message",
    "MAX_WIRE_CHARS",
    "generate_identity",
    "derive_address",
    "verify_agent_record",
    "encrypt",
    "decrypt",
]
