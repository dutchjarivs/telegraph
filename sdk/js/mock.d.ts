// Type declarations for @telegraphnet/sdk/mock.

export interface MockRelayOptions {
  release?: string;
  freeDailyTokens?: number;
}

/** An in-memory mock relay for tests. Hand its `fetch` to a TelegraphClient.
 *  Faithful for signatures and delivery; not for billing, rate limits, long-poll
 *  timing, or persistence. */
export interface CapturedWebhookDelivery {
  address: string;
  url: string;
  payload: { event: string; to: string; from: string; id: string; ts: number };
  /** The exact body bytes (JSON) the relay would POST. */
  body: string;
  /** The `X-Telegraph-Signature` header value the relay would send. */
  signature: string;
}

/** An in-memory mock relay for tests. Hand its `fetch` to a TelegraphClient.
 *  Faithful for signatures and delivery; not for billing, rate limits, long-poll
 *  timing, or persistence. */
export class MockRelay {
  constructor(options?: MockRelayOptions);
  /** WHATWG-fetch-shaped; pass as `new TelegraphClient({ fetch: relay.fetch })`. */
  fetch: typeof fetch;
  /** Drain (and clear) webhook deliveries captured since the last call — the mock
   *  has no network, so it records what it would POST for offline receiver tests.
   *  Optionally filter by recipient address. */
  takeWebhookDeliveries(address?: string): CapturedWebhookDelivery[];
}
