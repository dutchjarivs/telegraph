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

// Attachments ride *inside* the same sealed box as the text, so the relay is as
// blind to a file as it is to a message. They live in the structured envelope as
// `attachments: [{ name, mime, size, data }]`, where `data` is the attachment's
// bytes already base64-encoded (wire.js stays free of any platform base64 API so
// it byte-matches between the SDK and the relay repo). Because a receiver that
// predates attachments would silently drop them, a sender only packs them for a
// recipient that advertises ATTACHMENTS_CAPABILITY — a separate gate from
// threading, since parsing an envelope's text does not imply knowing how to
// surface its files.
export const ATTACHMENTS_CAPABILITY = 'attachments-v1';
// A single wire carries at most this many attachments; each name is bounded so a
// crafted envelope can't bloat the parsed object. These are envelope-shape
// guards, not the byte budget — total size is bounded by the relay's ciphertext
// cap (a big attachment is simply an expensive wire under the existing meter).
export const MAX_ATTACHMENTS = 16;
export const MAX_ATTACHMENT_NAME = 256;

// Normalize one caller-supplied attachment descriptor into the on-wire shape.
// `data` must already be a base64 string (the SDK encodes the raw bytes before
// calling packWire); `size` is the raw (pre-base64) byte length, carried so a
// receiver can show/limit it without decoding. name/mime get safe defaults.
function normalizeAttachment(a, i) {
  if (!a || typeof a !== 'object') throw new TypeError(`packWire: attachment ${i} must be an object`);
  if (typeof a.data !== 'string') throw new TypeError(`packWire: attachment ${i} data must be a base64 string`);
  const name = a.name == null ? `attachment-${i + 1}` : String(a.name).slice(0, MAX_ATTACHMENT_NAME);
  const mime = a.mime == null ? 'application/octet-stream' : String(a.mime).slice(0, MAX_ATTACHMENT_NAME);
  const size = Number.isInteger(a.size) && a.size >= 0 ? a.size : 0;
  return { name, mime, size, data: a.data };
}

// Pack a message plus optional threading metadata and/or attachments into the
// plaintext to seal. With no metadata it returns the bare string unchanged — so
// an ordinary send() still puts exactly the user's text on the wire, identical
// to 0.1.0.
export function packWire(text, { threadId, replyTo, priority, attachments } = {}) {
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
  if (attachments != null) {
    if (!Array.isArray(attachments)) throw new TypeError('packWire: attachments must be an array');
    if (attachments.length > MAX_ATTACHMENTS) {
      throw new RangeError(`packWire: at most ${MAX_ATTACHMENTS} attachments per wire`);
    }
    if (attachments.length > 0) env.attachments = attachments.map(normalizeAttachment);
  }
  // No metadata → stay bare (the common case; zero overhead, zero ambiguity).
  if (Object.keys(env).length === 0) return text;
  return JSON.stringify({ _tgv: WIRE_ENVELOPE_VERSION, text, ...env });
}

// Parse a decrypted plaintext into { text, threadId, replyTo, priority,
// attachments }. Defensive by construction: only a JSON object carrying the
// exact "_tgv":1 marker and a string `text` is read as a structured envelope.
// Everything else (a bare string, JSON without the marker, malformed JSON) comes
// back with the whole plaintext as `text` and null metadata — the 0.1.0 reading,
// so a plain message is never corrupted by a false envelope match. Attachments
// come back with `data` still base64 (the SDK decodes it for the caller).
export function unpackWire(plaintext) {
  const bare = { text: plaintext, threadId: null, replyTo: null, priority: null, attachments: [] };
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
    attachments: parseAttachments(obj.attachments),
  };
}

// Read an envelope's attachment list defensively: skip any entry that isn't a
// well-formed { data: base64-string } descriptor, and cap the count, so a
// hostile or corrupt envelope can't hand the caller a malformed file list.
function parseAttachments(raw) {
  if (!Array.isArray(raw)) return [];
  const out = [];
  for (const a of raw) {
    if (out.length >= MAX_ATTACHMENTS) break;
    if (!a || typeof a !== 'object' || typeof a.data !== 'string') continue;
    out.push({
      name: typeof a.name === 'string' ? a.name.slice(0, MAX_ATTACHMENT_NAME) : `attachment-${out.length + 1}`,
      mime: typeof a.mime === 'string' ? a.mime.slice(0, MAX_ATTACHMENT_NAME) : 'application/octet-stream',
      size: Number.isInteger(a.size) && a.size >= 0 ? a.size : 0,
      data: a.data,
    });
  }
  return out;
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
