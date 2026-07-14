// A real relay, booted for the Python SDK's tests.
//
// Not `bin/telegraph.js serve`, for one reason: the production default is 5 new
// registrations per IP per hour (anti-sybil), and a test suite legitimately
// creates a dozen agents from 127.0.0.1. The fix belongs here, in the test
// harness, and NOT in the relay's defaults — a limit that exists to stop sybil
// registration must not be loosened because it was inconvenient to a test.
//
// Everything else is the genuine article: the real createServer, the real
// crypto, the real HTTP surface. Prints the port it bound, then serves.
import { createServer } from '../../../src/server.js';

const dataDir = process.argv[2];
if (!dataDir) throw new Error('usage: node relay.js <dataDir>');

const server = createServer({
  dataDir,
  limits: { registerRate: { windowMs: 60_000, max: 10_000 } },
  adminToken: undefined, // no admin surface in tests, ever
});

server.listen(0, '127.0.0.1', () => {
  process.stdout.write(JSON.stringify({ port: server.address().port }) + '\n');
});

const shutdown = () => server.close(() => process.exit(0));
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
