import { test } from 'node:test';
import assert from 'node:assert/strict';
import { dechunk, isCloudflareIp, resolvesToCloudflare } from '../src/transport.js';
import { scan } from '../src/scanner.js';

test('isCloudflareIp', () => {
  assert.equal(isCloudflareIp('104.16.132.229'), true);
  assert.equal(isCloudflareIp('172.67.1.1'), true);
  assert.equal(isCloudflareIp('140.82.112.3'), false); // github.com
  assert.equal(isCloudflareIp('not-an-ip'), false);
});

test('dechunk', () => {
  const enc = new TextEncoder();
  assert.equal(new TextDecoder().decode(dechunk(enc.encode('5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n'))), 'hello world');
  assert.equal(new TextDecoder().decode(dechunk(enc.encode('5\r\nhel'))), 'hel'); // truncated read
});

const doh = (ips) => async () => Response.json({ Answer: ips.map((data) => ({ type: 1, data })) });

test('resolvesToCloudflare', async () => {
  assert.equal(await resolvesToCloudflare('a.example', { fetchImpl: doh(['104.16.1.1']) }), true);
  assert.equal(await resolvesToCloudflare('a.example', { fetchImpl: doh(['93.184.216.34']) }), false);
  assert.equal(await resolvesToCloudflare('a.example', { fetchImpl: async () => { throw new Error('x'); } }), null);
});

const edgeResponse = (extra) => async () =>
  new Response('<html></html>', {
    headers: { 'content-type': 'text/html', server: 'cloudflare', 'cf-ray': 'abc-KUL', 'cf-cache-status': 'DYNAMIC', 'x-phpchecker-transport': 'edge-fetch', ...extra },
  });

test('edge-fetch: Cloudflare-stamped headers are not mistaken for the target', async () => {
  const res = await scan('example.com', { fetchImpl: edgeResponse({ 'x-powered-by': 'PHP/8.4.20' }), dnsFetch: doh(['93.184.216.34']) });
  assert.equal(res.verdict, 'vulnerable');
  assert.equal(res.details.fingerprint.webserver, null);
  assert.equal(res.details.fingerprint.cdn, null);
  assert.ok(!res.context.includes('cloudflare'));
  assert.equal(res.details.request.transport, 'edge-fetch');
});

test('edge-fetch: DNS confirms a genuinely Cloudflare-hosted target', async () => {
  const res = await scan('example.com', { fetchImpl: edgeResponse({}), dnsFetch: doh(['104.16.1.1']) });
  assert.equal(res.details.fingerprint.cdn, 'Cloudflare');
  assert.ok(res.context.includes('cloudflare'));
});
