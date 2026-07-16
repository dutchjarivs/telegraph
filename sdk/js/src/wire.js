// Wire envelope — threading metadata that rides *inside* the sealed box.
//
// The relay never sees this. A wire's plaintext is end-to-end encrypted with
// nacl.box, so anything packed here (a thread id, a reply-to, a priority) is
// invisible to the relay and needs zero relay change — the relay keeps
// forwarding an opaque ciphertext exactly as it does for a plain message.
//
// Two plaintext forms travel over the wire, chosen so nothing old breaks:
//
//   • a bare string ....................... a plain message, byte-for-byte what
//                                            Telegraph shipped in 0.1.0.
//   • a JSON object with a "_tgv":1 marker . a structured wire: { text } plus
//                                            optional threadId / replyTo / priority.
//
// Backward compatibility rests on two rules:
//   1. A sender only produces the structured form for a recipient that
//      advertises WIRE_ENVELOPE_CAPABILITY in its directory record. A 0.1.0
//      agent never advertises it, so it never receives anything but bare
//      strings — it can't be handed JSON it doesn't understand.
//   2. unpackWire() only treats a plaintext as structured when it carries the
//      exact "_tgv":1 marker *and* a string `text`. Any other value — including
//      a message that merely happens to be JSON — is returned verbatim, so a
//      literal payload is never silently rewritten.
//
// Threading is deliberately client-side and relay-blind: the relay can't group,
// filter, or read threads, which keeps its promise (it can't read your mail)
// intact. Clients group by threadId locally — see groupThreads().

export const WIRE_ENVELOPE_VERSION = 1;
export const WIRE_ENVELOPE_CAPABILITY = 'wire-envelope-v1';
export const PRIORITIES = Object.freeze(['low', 'normal', 'high']);

// Pack a message plus optional threading metadata into the plaintext to seal.
// With no metadata it returns the bare string unchanged — so an ordinary
// send() still puts exactly the user's text on the wire, identical to 0.1.0.
export function packWire(text, { threadId, replyTo, priority } = {}) {
  if (typeof text !== 'string') throw new TypeError('packWire: text must be a string');
  const env = {};
  if (threadId != null) env.threadId = String(threadId);
  if (replyTo != null) env.replyTo = String(replyTo);
  if (priority != null) {
    if (!PRIORITIES.includes(priority)) {
      throw new RangeError(`packWire: priority must be one of ${PRIORITIES.join('|')}`);
    }
    env.priority = priority;
  }
  // No metadata → stay bare (the common case; zero overhead, zero ambiguity).
  if (Object.keys(env).length === 0) return text;
  return JSON.stringify({ _tgv: WIRE_ENVELOPE_VERSION, text, ...env });
}

// Parse a decrypted plaintext into { text, threadId, replyTo, priority }.
// Defensive by construction: only a JSON object carrying the exact "_tgv":1
// marker and a string `text` is read as a structured envelope. Everything else
// (a bare string, JSON without the marker, malformed JSON) comes back with the
// whole plaintext as `text` and null metadata — the 0.1.0 reading, so a plain
// message is never corrupted by a false envelope match.
export function unpackWire(plaintext) {
  const bare = { text: plaintext, threadId: null, replyTo: null, priority: null };
  // Fast reject: an envelope is always a JSON object, so it must start with '{'.
  if (typeof plaintext !== 'string' || plaintext.length === 0 || plaintext[0] !== '{') return bare;
  let obj;
  try {
    obj = JSON.parse(plaintext);
  } catch {
    return bare;
  }
  if (!obj || typeof obj !== 'object' || obj._tgv !== WIRE_ENVELOPE_VERSION || typeof obj.text !== 'string') {
    return bare;
  }
  return {
    text: obj.text,
    threadId: typeof obj.threadId === 'string' ? obj.threadId : null,
    replyTo: typeof obj.replyTo === 'string' ? obj.replyTo : null,
    priority: PRIORITIES.includes(obj.priority) ? obj.priority : null,
  };
}

// Group a list of inbox/sent wires into threads, client-side. A wire's thread
// is its threadId, or its own id when it has none (a wire that started no
// thread is a thread of one). Wires within a thread are ordered oldest-first
// by ts. Returns [{ threadId, wires }], newest-activity thread first.
export function groupThreads(messages) {
  const threads = new Map();
  for (const m of messages ?? []) {
    const key = m.threadId ?? m.id;
    if (!threads.has(key)) threads.set(key, []);
    threads.get(key).push(m);
  }
  const out = [];
  for (const [threadId, wires] of threads) {
    wires.sort((a, b) => (a.ts ?? 0) - (b.ts ?? 0));
    out.push({ threadId, wires });
  }
  // Most recently active thread first (by its newest wire).
  out.sort((a, b) => {
    const la = a.wires[a.wires.length - 1]?.ts ?? 0;
    const lb = b.wires[b.wires.length - 1]?.ts ?? 0;
    return lb - la;
  });
  return out;
}
