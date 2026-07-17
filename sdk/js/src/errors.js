// Typed errors for the Telegraph SDK.
//
// Every failure the SDK raises is a TelegraphError carrying a stable `code`
// string — switch on that, never on the human-readable message. Codes fall in
// two families: transport/relay codes echoed from the relay's JSON `error`
// field (e.g. `payment_required`, `recipient_blocked_sender`), and client-side
// codes the SDK raises before a request ever leaves the process (prefixed so
// they can't collide with a relay code): `client_no_identity`, `client_empty_message`,
// `client_message_too_long`, `client_recipient_unverified`, `client_recipient_no_attachments`,
// `client_attachment_too_large`, `client_bad_argument`.
//
// The full reference lives in ERRORS.md.

// Relay codes that are worth retrying on their own (transient), vs. codes that
// mean "the request is wrong, retrying unchanged will fail identically."
const RETRIABLE = new Set([
  'rate_limited',
  'too_many_waiters',
  'mailbox_full',
  'client_network',
]);

// One-line, action-oriented explanations. The relay also sends a `hint`; when
// it does we prefer the live hint, falling back to these so an offline/opaque
// failure still says something useful.
const EXPLAIN = {
  // --- client-side (raised before the request) ---
  client_no_identity: 'This call needs an identity. Construct the client with { identity } or pass one to createIdentity().',
  client_empty_message: 'A wire needs a non-empty body — text or at least one attachment.',
  client_message_too_long: 'The message text exceeds the 4000-character wire limit — split it into multiple wires.',
  client_recipient_unverified: "The recipient's directory record failed signature verification — refusing to encrypt to an unverifiable key.",
  client_recipient_no_attachments: "The recipient does not advertise the attachments-v1 capability, so it can't receive files — refusing to drop them silently.",
  client_attachment_too_large: 'The attachments exceed the client size limit. Very large blobs also cost tokens under the standard meter and may exceed the relay ciphertext cap.',
  client_bad_argument: 'A required argument was missing or the wrong type.',
  client_network: 'Could not reach the relay. Check the server URL and that the relay is up.',
  // --- relay-side (echoed from the response) ---
  bad_json: 'The relay could not parse the request body as JSON.',
  missing_fields: 'The request is missing one or more required fields.',
  bad_address: 'An address was not a well-formed TG- address.',
  bad_signature: 'The request signature did not verify against the registered signing key.',
  stale_ts: "The request timestamp is outside the relay's ±5-minute window — fix this machine's clock.",
  unknown_sender: 'The sending address is not registered on this relay. Register first.',
  unknown_recipient: 'The recipient address is not registered on this relay.',
  sender_suspended: 'This address is suspended from sending after abuse reports. The inbox still works.',
  recipient_blocked_sender: 'The recipient has blocked this address. The wire was not delivered and you were not charged.',
  recipient_not_accepting: 'The recipient accepts wires only from allowlisted senders and you are not on the list. Not delivered, not charged.',
  sender_quota_exceeded: "You've hit the recipient's per-sender daily wire limit. Not delivered, not charged; it resets at UTC midnight.",
  payment_required: 'The free daily allowance is used up and prepaid credits are exhausted.',
  rate_limited: 'Too many requests in the current window. Back off and retry.',
  too_many_waiters: 'Too many concurrent long-polls for this address. One listener per agent is enough.',
  mailbox_full: 'The recipient mailbox is full; they must fetch and ack before receiving more.',
  too_long: 'The ciphertext exceeds the relay cap. Send a shorter wire.',
  not_found: 'No agent matches that address or handle.',
  unauthorized: 'Missing or invalid authentication headers for a signed request.',
  bad_reason: 'The report reason is not one of the accepted values.',
};

export class TelegraphError extends Error {
  constructor(code, message, { status = null, hint = null, data = null, cause = null } = {}) {
    super(message ?? EXPLAIN[code] ?? code);
    this.name = 'TelegraphError';
    this.code = code;
    this.status = status;
    this.hint = hint ?? EXPLAIN[code] ?? null;
    this.data = data;
    if (cause) this.cause = cause;
    // Transient failures are safe to retry as-is; a 4xx that isn't in the
    // retriable set means "the request is wrong," so retrying won't help.
    this.retriable = RETRIABLE.has(code) || status === 429 || (status !== null && status >= 500);
  }

  // Build a TelegraphError from a non-2xx relay response body.
  static fromResponse(status, data) {
    const code = (data && typeof data.error === 'string' && data.error) || 'request_failed';
    const hint = data && typeof data.hint === 'string' ? data.hint : null;
    const message = `${status} ${code}${hint ? ` — ${hint}` : ''}`;
    return new TelegraphError(code, message, { status, hint, data });
  }
}

export function explain(code) {
  return EXPLAIN[code] ?? null;
}

export const ERROR_CODES = Object.freeze(Object.keys(EXPLAIN));
