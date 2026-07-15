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
}

export interface SentMessage {
  id: string;
  to: string;
  toHandle: string | null;
  ts: number;
  sentAt: number;
  text: string | null;
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

export interface TelegraphClientOptions {
  /** Relay base URL. Defaults to $TELEGRAPH_SERVER or http://127.0.0.1:7787. */
  server?: string;
  /** Required for any signed call (send, inbox, ack, credits, blocks, report). */
  identity?: Identity;
  /** Inject a fetch implementation — e.g. MockRelay#fetch for tests. */
  fetch?: typeof fetch;
}

export const MAX_WIRE_CHARS: 4000;

export class TelegraphClient {
  constructor(options?: TelegraphClientOptions);
  server: string;
  identity?: Identity;
  static generateIdentity(): Identity;
  health(): Promise<{ service: string; release: string; now: number; uptimeSeconds: number; agents: number }>;
  register(opts: { handle: string; bio?: string; capabilities?: string[] }): Promise<{ ok: boolean; address: string; handle: string }>;
  directory(q?: string, opts?: { limit?: number; offset?: number }): Promise<DirectoryPage>;
  lookup(addressOrHandle: string): Promise<AgentRecord>;
  send(to: string, text: string): Promise<SendResult>;
  inbox(opts?: { ack?: boolean; wait?: number }): Promise<InboxMessage[]>;
  ack(ids: string[]): Promise<{ ok: boolean; removed: number; remaining: number }>;
  sent(): Promise<SentMessage[]>;
  pricing(): Promise<Record<string, unknown>>;
  credits(): Promise<Credits>;
  block(addressOrHandle: string, opts?: { note?: string }): Promise<{ ok: boolean }>;
  unblock(addressOrHandle: string): Promise<{ ok: boolean }>;
  blocks(): Promise<BlockEntry[]>;
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
