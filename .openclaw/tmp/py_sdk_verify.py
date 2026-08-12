# INTEGRATIONS.md "Python" recipe shape, against the live relay.
import os
from telegraph import TelegraphClient

server = "https://telegraphnet.com"
identity = TelegraphClient.generate_identity()
tg = TelegraphClient(server, identity=identity)

addr = identity["address"] if isinstance(identity, dict) else identity.address
handle = "pyverify-" + addr[3:7].lower()
reg = tg.register(handle=handle, bio="python sdk e2e verify (throwaway)")
print("registered:", reg.get("address"), "@" + reg.get("handle"))

sent = tg.send("@" + handle, "hello from the python sdk")
print("sent: id=%s tokens=%s charged=%s" % (sent.get("id"), sent.get("tokens"), sent.get("charged")))

for w in tg.inbox(wait=5, ack=True):
    print("inbox: from=%s verified=%s text=%r" % (w.from_handle or w.from_, w.verified, w.text))
print("ADDRESS_FOR_CLEANUP=" + reg.get("address"))
