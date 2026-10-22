import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeTarget, ScanError } from '../src/validate.js';
import { scan, checkVersion } from '../src/scanner.js';
import worker from '../src/index.js';

test('SSRF guard rejects non-public targets', () => {
  for (const bad of [
    'http://127.0.0.1', 'localhost', 'http://10.0.0.1/', 'http://2130706433', 'http://[::1]/', 'intranet', 'a.local',
    'ftp://example.com', 'https://user:pw@example.com', 'https://example.com:22', '127.0.0.1.nip.io', 'x.localtest.me', 'host.home.arpa',
  ]) {
    assert.throws(() => normalizeTarget(bad), ScanError, bad);
  }
  assert.equal(normalizeTarget('Example.com/path').hostname, 'example.com');
});

function mockFetch(routes) {
  return async (url) => {
    const r = routes[url];
    if (!r) throw new Error('no route ' + url);
    return new Response(r.body ?? '<html></html>', { status: r.status ?? 200, headers: r.headers ?? { 'content-type': 'text/html' } });
  };
}
const html = (headers, body) => ({ headers: { 'content-type': 'text/html', ...headers }, body });

test('scan: vulnerable banner on stock nginx', async () => {
  const res = await scan('example.com', { fetchImpl: mockFetch({ 'https://example.com/': html({ server: 'nginx', 'x-powered-by': 'PHP/8.3.30' }) }) });
  assert.equal(res.verdict, 'vulnerable');
  assert.equal(res.php.fixedIn, '8.3.36');
  assert.equal(res.details.fingerprint.webserver.name, 'nginx');
  assert.ok(res.details.checks.some((c) => c.name.includes('CVE-2026-109618') && c.name.includes('CVE-2026-109619')));
  assert.ok(res.details.checks.some((c) => c.name === 'Exploit attempts' && c.status === 'skipped'));
});

test('scan: version is read from the PHP token, not other products', async () => {
  const res = await scan('example.com', { fetchImpl: mockFetch({ 'https://example.com/': html({ 'x-powered-by': 'PleskLin 18.0.5, PHP/7.4.33' }) }) });
  assert.equal(res.php.version, '7.4.33');
  assert.equal(res.verdict, 'vulnerable');
});

test('scan: Ubuntu build is "verify" and OS is fingerprinted', async () => {
  const res = await scan('https://example.com', {
    fetchImpl: mockFetch({ 'https://example.com/': html({ server: 'Apache/2.4.52 (Ubuntu)', 'x-powered-by': 'PHP/8.1.2-1ubuntu2.14' }) }),
  });
  assert.equal(res.verdict, 'verify');
  assert.equal(res.details.fingerprint.os.name, 'Ubuntu');
  assert.equal(res.details.fingerprint.os.release, '22.04');
});

test('scan: official Docker image on Debian is not mistaken for a distro backport', async () => {
  const res = await scan('example.com', {
    fetchImpl: mockFetch({ 'https://example.com/': html({ server: 'Apache/2.4.62 (Debian)', 'x-powered-by': 'PHP/8.3.30' }) }),
  });
  assert.equal(res.verdict, 'vulnerable');
});

test('scan: hidden version / no PHP / SAPI only claimed for PHP sites', async () => {
  const hidden = await scan('example.com', { fetchImpl: mockFetch({ 'https://example.com/': html({ 'set-cookie': 'PHPSESSID=abc; path=/', server: 'nginx' }) }) });
  assert.equal(hidden.verdict, 'unknown');
  assert.ok(hidden.findings.some((f) => f.id === 'sapi'));
  const none = await scan('example.com', { fetchImpl: mockFetch({ 'https://example.com/': html({ server: 'nginx' }) }) });
  assert.equal(none.verdict, 'no-php');
  assert.ok(!none.findings.some((f) => f.id === 'sapi'));
});

test('scan: WordPress via Link header counts as PHP evidence', async () => {
  const res = await scan('example.com', {
    fetchImpl: mockFetch({ 'https://example.com/': html({ link: '<https://example.com/wp-json/>; rel="https://api.w.org/"' }) }),
  });
  assert.equal(res.verdict, 'unknown');
  assert.ok(res.context.includes('wordpress'));
});

test('scan: redirect to a private address is not followed but earlier hops are reported', async () => {
  const res = await scan('example.com', {
    fetchImpl: mockFetch({ 'https://example.com/': { status: 302, headers: { location: 'http://127.0.0.1/admin', 'x-powered-by': 'PHP/8.2.20' } } }),
  });
  assert.equal(res.verdict, 'vulnerable');
  assert.ok(res.findings.some((f) => f.id === 'redirect-blocked'));
});

test('scan: follows a public redirect, detects CDN and CMS', async () => {
  const res = await scan('example.com', {
    fetchImpl: mockFetch({
      'https://example.com/': { status: 301, headers: { location: 'https://www.example.com/' } },
      'https://www.example.com/': html({ 'x-powered-by': 'PHP/8.5.12', server: 'cloudflare', 'cf-ray': 'x' }, '<link href="/wp-content/a.css">'),
    }),
  });
  assert.equal(res.verdict, 'patched');
  assert.equal(res.redirects.length, 1);
  assert.ok(res.context.includes('cloudflare') && res.context.includes('wordpress'));
  assert.equal(res.details.fingerprint.cdn, 'Cloudflare');
});

test('scan: HTTP errors and bot challenges are flagged', async () => {
  const res = await scan('example.com', {
    fetchImpl: mockFetch({ 'https://example.com/': { status: 403, headers: { 'content-type': 'text/html', 'cf-mitigated': 'challenge', server: 'cloudflare' } } }),
  });
  assert.ok(res.findings.some((f) => f.id === 'http-error' && /challenge/.test(f.detail)));
});

test('checkVersion', () => {
  assert.equal(checkVersion('8.4.27').verdict, 'patched');
  assert.equal(checkVersion('PHP/7.4.33').verdict, 'vulnerable');
  assert.equal(checkVersion('8.1.2-1ubuntu2.14').verdict, 'verify');
  assert.throws(() => checkVersion('hello'), ScanError);
});

test('worker routes, consent, cross-site guard, CORS, logging', async () => {
  const logs = [];
  const orig = console.log;
  console.log = (s) => logs.push(s);
  try {
    const home = await worker.fetch(new Request('https://x/'), {});
    assert.match(home.headers.get('content-security-policy'), /nonce-/);
    const page = await home.text();
    assert.match(page, /CVE-2026-109618/);
    assert.match(page, /out-of-memory handling vulnerability/);
    assert.match(page, /use-after-free vulnerability/);
    assert.match(page, /Open source/);
    assert.match(page, /Only scan requests are logged/);
    assert.doesNotMatch(page, /__[A-Z]+__/);

    const noConsent = await worker.fetch(new Request('https://x/api/scan?url=example.com'), {});
    assert.equal(noConsent.status, 400);
    assert.equal((await noConsent.json()).error, 'consent_required');
    assert.equal(noConsent.headers.get('access-control-allow-origin'), null);

    const xsite = await worker.fetch(new Request('https://x/api/scan?authorized=1&url=example.com', { headers: { 'sec-fetch-site': 'cross-site' } }), {});
    assert.equal(xsite.status, 403);

    const bad = await worker.fetch(new Request('https://x/api/scan?authorized=1&url=127.0.0.1', { headers: { 'cf-connecting-ip': '203.0.113.9' } }), {});
    assert.equal(bad.status, 400);

    const ver = await worker.fetch(new Request('https://x/api/version?v=8.2.34'), {});
    assert.equal((await ver.json()).verdict, 'vulnerable');
    assert.equal(ver.headers.get('access-control-allow-origin'), '*');

    const res = await worker.fetch(new Request('https://x/api/resources'), {});
    const data = await res.json();
    assert.ok(data.items.length > 40);
    assert.ok(!data.items.some((i) => /^\d+ ·/.test(i.title)), 'guide titles are unnumbered');
  } finally {
    console.log = orig;
  }
  const entries = logs.map((l) => JSON.parse(l));
  assert.ok(entries.every((e) => e.kind === 'scan'), 'only scan requests are logged');
  assert.ok(entries.some((e) => e.outcome === 'error' && e.error === 'ip_literal' && e.ip === '203.0.113.9'));
  assert.ok(entries.some((e) => e.error === 'cross_site'));
});
