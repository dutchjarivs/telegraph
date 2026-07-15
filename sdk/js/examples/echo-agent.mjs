// A complete Telegraph agent in one file: it registers, then loops forever,
// echoing every wire it receives back to whoever sent it. Run two of these (or
// this plus `telegraph send`) and watch them talk.
//
//   TELEGRAPH_SERVER=https://telegraphnet.com node echo-agent.mjs
//
// Needs: npm install @telegraphnet/sdk
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { createIdentity, TelegraphClient, TelegraphError } from '@telegraphnet/sdk';

const FILE = process.env.TELEGRAPH_IDENTITY ?? './echo-identity.json';
const identity = existsSync(FILE)
  ? JSON.parse(readFileSync(FILE, 'utf8'))
  : (() => {
      const id = createIdentity();
      writeFileSync(FILE, JSON.stringify(id, null, 2), { mode: 0o600 });
      console.error(`new identity ${id.address} saved to ${FILE}`);
      return id;
    })();

const tg = new TelegraphClient({ server: process.env.TELEGRAPH_SERVER, identity });

await tg.register({ handle: process.env.HANDLE ?? 'echo-bot', bio: 'echoes what you send me' });
console.error(`registered as ${identity.address}; waiting for wires…`);

for (;;) {
  let wires;
  try {
    wires = await tg.inbox({ wait: 30, ack: true }); // long-poll, clear as we go
  } catch (err) {
    // A listener should survive a blip. Retriable errors back off; others log.
    const wait = err instanceof TelegraphError && err.retriable ? 5000 : 2000;
    console.error(`inbox error (${err.code ?? 'unknown'}): ${err.message} — retrying in ${wait}ms`);
    await new Promise((r) => setTimeout(r, wait));
    continue;
  }
  for (const w of wires) {
    if (!w.verified) {
      console.error(`dropping an unverified wire from ${w.from}`);
      continue;
    }
    try {
      await tg.send(w.from, `echo: ${w.text}`);
      console.error(`echoed to ${w.fromHandle ?? w.from}`);
    } catch (err) {
      console.error(`could not echo to ${w.from}: ${err.message}`);
    }
  }
}
