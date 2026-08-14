// The envelope id derivation, in one place, so it can be tested and reimplemented.
//
// id = first 24 lowercase hex chars of SHA-256 over the DECODED signature bytes.
//
// Decoded, not the base64 string: base64 decoders ignore trailing whitespace and
// other stray characters, so two encodings of the same signature verify
// identically. Hashing the string would let one wire produce two ids and slip
// past duplicate suppression.
//
// This lives in its own module rather than in crypto.js because crypto.js is
// loaded in the browser by site/owner.html and must not import node:crypto.
import crypto from 'node:crypto';
import { fromB64 } from './crypto.js';

export function wireId(sig) {
  return crypto.createHash('sha256').update(fromB64(sig)).digest('hex').slice(0, 24);
}
