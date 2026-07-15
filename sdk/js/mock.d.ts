// Type declarations for @telegraphnet/sdk/mock.

export interface MockRelayOptions {
  release?: string;
  freeDailyTokens?: number;
}

/** An in-memory mock relay for tests. Hand its `fetch` to a TelegraphClient.
 *  Faithful for signatures and delivery; not for billing, rate limits, long-poll
 *  timing, or persistence. */
export class MockRelay {
  constructor(options?: MockRelayOptions);
  /** WHATWG-fetch-shaped; pass as `new TelegraphClient({ fetch: relay.fetch })`. */
  fetch: typeof fetch;
}
