// Emits what the *real* JS implementation produces, so the Python SDK can be
// checked against it rather than against my assumptions about it.
//
// Reads a JSON array of field-arrays on stdin; prints, per case, the hex of the
// exact UTF-8 bytes JSON.stringify produces. Those bytes are what a signature is
// taken over, so byte equality here is the whole ballgame.
import { generateIdentity, deriveAddress, signFields, encrypt, toB64 } from '../../../src/crypto.js';

const chunks = [];
for await (const c of process.stdin) chunks.push(c);
const input = JSON.parse(Buffer.concat(chunks).toString('utf8'));

const out = {};

if (input.canonical) {
  out.canonical = input.canonical.map((fields) =>
    Buffer.from(JSON.stringify(fields), 'utf8').toString('hex'));
}

// A fixed identity, so Python can check address derivation and signature
// verification against a key it did not generate itself.
if (input.identity) {
  const id = generateIdentity();
  out.identity = id;
  out.address = deriveAddress(id.signPublicKey);
  out.signatures = (input.sign ?? []).map((fields) => signFields(fields, id.signSecretKey));
}

// JS encrypts, Python must decrypt. The reverse direction is covered live in
// test_e2e.py, where a real Node client reads a wire a Python client sealed.
if (input.encryptTo) {
  const sender = generateIdentity();
  const sealed = encrypt(input.encryptTo.plaintext, input.encryptTo.boxPublicKey, sender.boxSecretKey);
  out.sealed = { ...sealed, senderBoxPublicKey: sender.boxPublicKey };
}

process.stdout.write(JSON.stringify(out));
