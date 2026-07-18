// Telegraph crypto layer.
// Identity = Ed25519 signing keypair (who you are) + X25519 box keypair (how you receive).
// Address = base32 of the first 10 bytes of SHA-512(signPublicKey) — a phone number for agents.
// E2EE = nacl.box (X25519 + XSalsa20-Poly1305): the relay never sees plaintext.
import nacl from 'tweetnacl';

const B32 = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32
const te = new TextEncoder();
const td = new TextDecoder();

export const REGISTER_TAG = 'telegraph-register-v1';
export const MESSAGE_TAG = 'telegraph-message-v1';
export const AUTH_TAG = 'telegraph-auth-v1';
export const RECEIPT_TAG = 'telegraph-receipt-v1';

export function toB64(u8) {
  return Buffer.from(u8).toString('base64');
}

export function fromB64(s) {
  return new Uint8Array(Buffer.from(s, 'base64'));
}

export function generateIdentity() {
  const sign = nacl.sign.keyPair();
  const box = nacl.box.keyPair();
  return {
    version: 1,
    address: deriveAddress(sign.publicKey),
    signPublicKey: toB64(sign.publicKey),
    signSecretKey: toB64(sign.secretKey),
    boxPublicKey: toB64(box.publicKey),
    boxSecretKey: toB64(box.secretKey),
  };
}

export function deriveAddress(signPublicKey) {
  const pub = typeof signPublicKey === 'string' ? fromB64(signPublicKey) : signPublicKey;
  if (pub.length !== 32) throw new Error('bad signPublicKey');
  const digest = nacl.hash(pub).slice(0, 10); // SHA-512, first 80 bits
  let bits = 0;
  let acc = 0;
  let out = '';
  for (const byte of digest) {
    acc = (acc << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      out += B32[(acc >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  return `TG-${out.slice(0, 4)}-${out.slice(4, 8)}-${out.slice(8, 12)}-${out.slice(12, 16)}`;
}

// Canonical signing payloads: JSON.stringify of a fixed-order array, UTF-8 bytes.
export function registerFields(handle, signPublicKey, boxPublicKey, bio, capabilities, ts) {
  return [REGISTER_TAG, handle, signPublicKey, boxPublicKey, bio, capabilities, ts];
}

export function messageFields(to, from, nonce, ciphertext, ts) {
  return [MESSAGE_TAG, to, from, nonce, ciphertext, ts];
}

export function authFields(method, path, bodyHash, ts) {
  return [AUTH_TAG, method.toUpperCase(), path, bodyHash, ts];
}

// A delivery receipt: the recipient signs that they fetched-and-acked a specific
// wire from a specific sender at a time. Bound to (messageId, sender, recipient)
// so a receipt can't be replayed for a different wire or claimed by another party.
export function receiptFields(messageId, sender, recipient, at) {
  return [RECEIPT_TAG, messageId, sender, recipient, at];
}

export function signFields(fields, signSecretKeyB64) {
  return toB64(nacl.sign.detached(te.encode(JSON.stringify(fields)), fromB64(signSecretKeyB64)));
}

export function verifyFields(fields, sigB64, signPublicKeyB64) {
  try {
    return nacl.sign.detached.verify(
      te.encode(JSON.stringify(fields)),
      fromB64(sigB64),
      fromB64(signPublicKeyB64),
    );
  } catch {
    return false;
  }
}

export function encrypt(plaintext, recipientBoxPublicKeyB64, senderBoxSecretKeyB64) {
  const nonce = nacl.randomBytes(nacl.box.nonceLength);
  const ciphertext = nacl.box(
    te.encode(plaintext),
    nonce,
    fromB64(recipientBoxPublicKeyB64),
    fromB64(senderBoxSecretKeyB64),
  );
  return { nonce: toB64(nonce), ciphertext: toB64(ciphertext) };
}

export function decrypt(nonceB64, ciphertextB64, senderBoxPublicKeyB64, recipientBoxSecretKeyB64) {
  try {
    const plaintext = nacl.box.open(
      fromB64(ciphertextB64),
      fromB64(nonceB64),
      fromB64(senderBoxPublicKeyB64),
      fromB64(recipientBoxSecretKeyB64),
    );
    return plaintext ? td.decode(plaintext) : null;
  } catch {
    return null;
  }
}

// A directory record is self-signed at registration. Verifying it proves the
// handle and boxPublicKey are bound to the signing key, and the address is
// derived from that key — so a malicious relay cannot swap keys undetected.
export function verifyAgentRecord(agent) {
  if (!agent || typeof agent.sig !== 'string') return false;
  try {
    const fields = registerFields(
      agent.handle,
      agent.signPublicKey,
      agent.boxPublicKey,
      agent.bio ?? '',
      agent.capabilities ?? [],
      agent.ts,
    );
    return (
      verifyFields(fields, agent.sig, agent.signPublicKey) &&
      deriveAddress(agent.signPublicKey) === agent.address
    );
  } catch {
    return false;
  }
}
