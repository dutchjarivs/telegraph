// SSRF guard: the private/reserved-range classifier and URL parser that keep a
// webhook from turning the relay into an attacker's proxy into its own network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isBlockedIp, parseWebhookUrl, ipVersion } from '../src/ssrf.js';

test('blocks the IPv4 ranges that must never be a webhook target', () => {
  for (const ip of [
    '127.0.0.1', '127.1.2.3',        // loopback
    '10.0.0.1', '10.255.255.255',    // private
    '172.16.0.1', '172.31.255.255',  // private
    '192.168.1.1',                   // private
    '169.254.169.254',               // link-local / cloud metadata
    '100.64.0.1',                    // CGNAT
    '0.0.0.0',                       // unspecified
    '198.18.0.1',                    // benchmarking
    '192.0.2.5', '198.51.100.5', '203.0.113.5', // TEST-NET
    '224.0.0.1', '239.1.1.1',        // multicast
    '255.255.255.255',               // broadcast
    '240.0.0.1',                     // reserved
  ]) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
});

test('allows ordinary public IPv4', () => {
  for (const ip of ['1.1.1.1', '8.8.8.8', '93.184.216.34', '172.15.0.1', '172.32.0.1', '192.167.0.1', '100.63.0.1', '100.128.0.1']) {
    assert.equal(isBlockedIp(ip), false, `${ip} should be allowed`);
  }
});

test('blocks IPv6 loopback, link-local, ULA, unspecified, multicast, and mapped v4', () => {
  for (const ip of [
    '::1',                    // loopback
    '::',                     // unspecified
    'fe80::1',                // link-local
    'fc00::1', 'fd12:3456::1',// unique-local
    'ff02::1',                // multicast
    '2001:db8::1',            // documentation
    '::ffff:127.0.0.1',       // mapped loopback — the classic smuggle
    '::ffff:10.0.0.1',        // mapped private
    '::ffff:169.254.169.254', // mapped metadata
  ]) {
    assert.equal(isBlockedIp(ip), true, `${ip} should be blocked`);
  }
});

test('allows a public IPv6', () => {
  assert.equal(isBlockedIp('2606:4700:4700::1111'), false); // cloudflare dns
  assert.equal(isBlockedIp('::ffff:8.8.8.8'), false);       // mapped public v4
});

test('a non-IP string is treated as blocked (fail closed)', () => {
  assert.equal(isBlockedIp('not-an-ip'), true);
  assert.equal(isBlockedIp(''), true);
});

test('ipVersion classifies literals but not hostnames', () => {
  assert.equal(ipVersion('1.2.3.4'), 4);
  assert.equal(ipVersion('::1'), 6);
  assert.equal(ipVersion('example.com'), 0);
  assert.equal(ipVersion('999.1.1.1'), 0); // not a valid octet → not a v4 literal
});

test('parseWebhookUrl requires https', () => {
  assert.throws(() => parseWebhookUrl('http://example.com/hook'), (e) => e.reason === 'not_https');
  assert.throws(() => parseWebhookUrl('ftp://example.com'), (e) => e.reason === 'not_https');
  assert.throws(() => parseWebhookUrl('not a url'), (e) => e.reason === 'bad_url');
});

test('parseWebhookUrl refuses an IP-literal host in a blocked range', () => {
  assert.throws(() => parseWebhookUrl('https://127.0.0.1/hook'), (e) => e.reason === 'blocked_ip');
  assert.throws(() => parseWebhookUrl('https://169.254.169.254/latest/meta-data'), (e) => e.reason === 'blocked_ip');
  assert.throws(() => parseWebhookUrl('https://[::1]/hook'), (e) => e.reason === 'blocked_ip');
});

test('parseWebhookUrl refuses embedded credentials', () => {
  assert.throws(() => parseWebhookUrl('https://user:pass@example.com/hook'), (e) => e.reason === 'has_credentials');
});

test('parseWebhookUrl accepts a normal https URL and defaults the port', () => {
  const p = parseWebhookUrl('https://hooks.example.com/telegraph');
  assert.equal(p.hostname, 'hooks.example.com');
  assert.equal(p.port, 443);
});
