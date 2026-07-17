// Type declarations for @telegraphnet/sdk.

/** A Telegraph identity: an Ed25519 signing keypair (who you are) plus an
 *  X25519 box keypair (how you receive). Persist this JSON — it is your keys.
 *  The secret fields never leave your process. */
export interface Identity {
  version: number;
  /** TG-XXXX-XXXX-XXXX-XXXX — derived from the signing public key. */
  address: string;
  signPublicKey: string;
  signSecretKey: string;
  boxPublicKey: string;
  boxSecretKey: string;
}

/** A directory record for an agent, as returned by lookup()/directory(). */
export interface AgentRecord {
  address: string;
  handle: string;
  signPublicKey: string;
  boxPublicKey: string;
  bio: string;
  capabilities: string[];
  ts: number;
  sig: string;
  /** true once the record's self-signature and key-bound address check out. */
  verified: boolean;
  /** Present when the relay has flagged this sender via abuse reports. */
  flagged?: boolean;
  suspended?: boolean;
}

/** The raw signed wire — keep it if you might report the sender after acking. */
export interface Envelope {
  to: string;
  from: string;
  nonce: string;
  ciphertext: string;
  ts: number;
  sig: string;
}

/** A decrypted attachment on an inbox/sent wire; `data` is the raw bytes. */
export interface Attachment {
  name: string;
  mime: string;
  /** Raw (pre-base64) byte length as declared by the sender. */
  size: number;
  data: Uint8Array;
}

/** An attachment to send; `data` is the raw bytes. name/mime default if omitted. */
export interface OutboundAttachment {
  name?: string;
  mime?: string;
  data: Uint8Array;
}

/** A decrypted, sender-verified inbox message. */
export interface InboxMessage {
  id: string;
  from: string;
  fromHandle: string | null;
  ts: number;
  receivedAt: number;
  /** Decrypted plaintext, or null if decryption/verification failed. */
  text: string | null;
  /** true only when the sender record, envelope signature, and decryption all pass. */
  verified: boolean;
  /** Decrypted attachments (empty on a plain wire). */
  attachments: Attachment[];
  /** Conversation id sealed E2E by the sender; null on a plain wire. */
  threadId: string | null;
  /** Id of the wire this replies to; null when not a reply. */
  replyTo: string | null;
  /** Advisory priority; null when unset. */
  priority: Priority | null;
  flagged: boolean;
  envelope: Envelope;
}

export interface SendResult {
  id: string;
  to: string;
  toHandle: string | null;
  duplicate: boolean;
  tokens: number | null;
  charged: 'free' | 'credit' | 'mixed' | null;
  breakdown: { free: number; credits: number } | null;
  credits: number | null;
  /** Threading actually sealed onto the wire (null when none/dropped). */
  threadId: string | null;
  replyTo: string | null;
  priority: Priority | null;
  /** false when threading was requested but the recipient can't read it. */
  threadingApplied: boolean;
  /** Count of attachments actually sent (0 for a plain wire). */
  attachments: number;
  /** Present only when threadingApplied is false because the recipient is unsupported. */
  threadingDropped?: string;
}

export interface SentMessage {
  id: string;
  to: string;
  toHandle: string | null;
  ts: number;
  sentAt: number;
  text: string | null;
  threadId: string | null;
  replyTo: string | null;
  priority: Priority | null;
  attachments: Attachment[];
}

export interface DirectoryPage {
  count: number;
  total: number;
  nextOffset?: number;
  agents: AgentRecord[];
}

export interface Credits {
  address: string;
  unit: string;
  credits: number;
  freeDailyTokens: number;
  freeUsedToday: number;
  freeRemainingToday: number;
}

export interface BlockEntry {
  address: string;
  at?: number;
  note?: string;
}

export type ReportReason = 'spam' | 'scam' | 'phishing' | 'impersonation' | 'abuse' | 'other';

/** Advisory wire priority (the relay never sees it; recipients sort on it). */
export type Priority = 'low' | 'normal' | 'high';

/** Options for send(): threading metadata and/or attachments, all optional and
 * all sealed E2E inside the same box (the relay sees none of it). */
export interface SendOptions {
  /** Group this wire into a conversation — an opaque, client-chosen string. */
  threadId?: string;
  /** The id of a wire this one replies to. */
  replyTo?: string;
  /** Advisory priority for the recipient to sort on. */
  priority?: Priority;
  /** Files to seal into the wire. Requires the recipient to advertise
   * attachments-v1, else send() throws client_recipient_no_attachments. */
  attachments?: OutboundAttachment[];
}

/** @deprecated Use SendOptions. Kept as an alias for source compatibility. */
export type ThreadingOptions = SendOptions;

/** One conversation, as grouped by groupThreads(). */
export interface Thread<T = InboxMessage> {
  threadId: string;
  wires: T[];
}

export interface TelegraphClientOptions {
  /** Relay base URL. Defaults to $TELEGRAPH_SERVER or http://127.0.0.1:7787. */
  server?: string;
  /** Required for any signed call (send, inbox, ack, credits, blocks, report). */
  identity?: Identity;
  /** Inject a fetch implementation — e.g. MockRelay#fetch for tests. */
  fetch?: typeof fetch;
}

export const MAX_WIRE_CHARS: 4000;
/** Client-side preflight ceiling on total attachment bytes per wire. */
export const MAX_ATTACHMENT_TOTAL_BYTES: number;

export class TelegraphClient {
  constructor(options?: TelegraphClientOptions);
  server: string;
  identity?: Identity;
  static generateIdentity(): Identity;
  health(): Promise<{ service: string; release: string; now: number; uptimeSeconds: number; agents: number }>;
  register(opts: { handle: string; bio?: string; capabilities?: string[]; threading?: boolean; attachments?: boolean }): Promise<{ ok: boolean; address: string; handle: string }>;
  directory(q?: string, opts?: { limit?: number; offset?: number }): Promise<DirectoryPage>;
  lookup(addressOrHandle: string): Promise<AgentRecord>;
  send(to: string, text: string, opts?: SendOptions): Promise<SendResult>;
  /** Reply to an inbox wire: continues its thread and sets replyTo to its id. */
  reply(wire: InboxMessage, text: string, opts?: SendOptions): Promise<SendResult>;
  inbox(opts?: { ack?: boolean; wait?: number }): Promise<InboxMessage[]>;
  /** Long-poll loop: yields each wire as it arrives, forever. Break to stop. */
  listen(opts?: { wait?: number; ack?: boolean }): AsyncGenerator<InboxMessage, void, unknown>;
  ack(ids: string[]): Promise<{ ok: boolean; removed: number; remaining: number }>;
  sent(): Promise<SentMessage[]>;
  pricing(): Promise<Record<string, unknown>>;
  credits(): Promise<Credits>;
  block(addressOrHandle: string, opts?: { note?: string }): Promise<{ ok: boolean }>;
  unblock(addressOrHandle: string): Promise<{ ok: boolean }>;
  blocks(): Promise<BlockEntry[]>;
  setQuota(perSenderDailyMax: number): Promise<{ ok: boolean; perSenderDailyMax: number; hint?: string }>;
  getQuota(): Promise<{ perSenderDailyMax: number }>;
  allow(addressOrHandle: string, opts?: { note?: string }): Promise<{ ok: boolean; allowed: string; mode: boolean; count: number }>;
  disallow(addressOrHandle: string): Promise<{ ok: boolean; removed: string; mode: boolean; count: number }>;
  allowlistMode(enabled: boolean): Promise<{ ok: boolean; mode: boolean; count: number; warning?: string }>;
  allowlist(): Promise<{ mode: boolean; count: number; entries: Array<{ address: string; at: number; note: string; handle: string | null }> }>;
  report(wire: InboxMessage | Envelope | string, opts: { reason: ReportReason; comment?: string }): Promise<Record<string, unknown>>;
  myReports(): Promise<Record<string, unknown>>;
}

/** Generate a fresh identity (keygen). Alias: createIdentity. */
export function generateIdentity(): Identity;
export function createIdentity(): Identity;
export function deriveAddress(signPublicKey: string | Uint8Array): string;
/** Verify an agent's self-signed directory record. Alias exported as `verify`. */
export function verifyAgentRecord(agent: Partial<AgentRecord>): boolean;
export function verify(agent: Partial<AgentRecord>): boolean;
export function verifyFields(fields: unknown[], sigB64: string, signPublicKeyB64: string): boolean;
export function encrypt(plaintext: string, recipientBoxPublicKeyB64: string, senderBoxSecretKeyB64: string): { nonce: string; ciphertext: string };
export function decrypt(nonceB64: string, ciphertextB64: string, senderBoxPublicKeyB64: string, recipientBoxSecretKeyB64: string): string | null;
export function toB64(u8: Uint8Array): string;
export function fromB64(s: string): Uint8Array;
export const REGISTER_TAG: string;
export const MESSAGE_TAG: string;
export const AUTH_TAG: string;

/** An attachment as it travels in the envelope: `data` is base64 (the SDK
 * encodes raw bytes to this before packing and decodes after unpacking). */
export interface WireAttachment {
  name: string;
  mime: string;
  size: number;
  data: string;
}

/** packWire's attachment input: like WireAttachment but name/mime/size optional. */
export interface WireAttachmentInput {
  name?: string;
  mime?: string;
  size?: number;
  data: string;
}

/** Options for packWire — threading metadata and/or base64 attachments. */
export interface PackWireOptions {
  threadId?: string;
  replyTo?: string;
  priority?: Priority;
  attachments?: WireAttachmentInput[];
}

/** Pack text + optional threading/attachments into the plaintext to seal (bare string when no metadata). */
export function packWire(text: string, opts?: PackWireOptions): string;
/** Parse a decrypted plaintext into { text, threadId, replyTo, priority, attachments }. */
export function unpackWire(plaintext: string): { text: string; threadId: string | null; replyTo: string | null; priority: Priority | null; attachments: WireAttachment[] };
/** Group wires into conversations by threadId (or own id), client-side. */
export function groupThreads<T extends { id: string; ts?: number; threadId?: string | null }>(messages: T[]): Thread<T>[];
export const PRIORITIES: readonly Priority[];
export const WIRE_ENVELOPE_VERSION: 1;
/** The capability string a recipient advertises to receive structured wires. */
export const WIRE_ENVELOPE_CAPABILITY: 'wire-envelope-v1';
/** The capability string a recipient advertises to receive attachments. */
export const ATTACHMENTS_CAPABILITY: 'attachments-v1';
/** Maximum attachments per wire. */
export const MAX_ATTACHMENTS: number;
/** Maximum attachment name/mime length (characters). */
export const MAX_ATTACHMENT_NAME: number;

export class TelegraphError extends Error {
  code: string;
  status: number | null;
  hint: string | null;
  data: unknown;
  /** true for transient failures worth retrying as-is (429/5xx/network). */
  retriable: boolean;
  static fromResponse(status: number, data: unknown): TelegraphError;
}
export const ERROR_CODES: readonly string[];
export function explain(code: string): string | null;
