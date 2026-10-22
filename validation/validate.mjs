#!/usr/bin/env node
// End-to-end validation: runs the real scanner (src/scanner.js) over real TCP/HTTP against
//   1. header profiles of real-world PHP stacks (validation/profiles.mjs), and
//   2. real PHP interpreters found on this machine, served with `php -S`.
// Each target gets a public-looking hostname that is routed to 127.0.0.1; everything else
// (request building, redirects, header parsing, verdicts) is the production code path.
//
// It also verifies the passive-scanning promises: only body-less GETs are sent, the HTML
// read stops at 64 KB, the overall timeout fires, and private redirects are not followed.
//
// Usage: node validation/validate.mjs [--no-php]
import http from 'node:http';
import { spawn } from 'node:child_process';
import { existsSync, readdirSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { scan } from '../src/scanner.js';
import { PROFILES } from './profiles.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DOMAIN = 'phpchecker-validation.com';

// Independent oracle written from the advisory text – deliberately NOT imported from src/.
// Affected: 5.4.0 – 8.5.11. Fixed: 8.2.35, 8.3.36, 8.4.27, 8.5.12. 5.4 – 8.1 never get a fix.
const FIXED = { '8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12 };
function oracle(version) {
  // Distro packages (not Surý/Remi upstream repackages) may carry backports the number can't show.
  const [ma, mi, pa] = version.split(/[^0-9]+/).map(Number);
  if (ma < 5 || (ma === 5 && mi < 4)) return 'verify';
  if (ma > 8 || (ma === 8 && mi > 5)) return 'patched';
  if (ma < 8 || mi < 2) return 'vulnerable';
  return pa >= FIXED[`${ma}.${mi}`] ? 'patched' : 'vulnerable';
}

// ---------- routing: public-looking hostnames -> local ports ----------
const routes = new Map(); // hostname -> port
const dns = new Map(); // hostname -> A records for the DNS-over-HTTPS stand-in
const requestLog = []; // every request any test server received

function routedFetch(url, init) {
  const u = new URL(url);
  const port = routes.get(u.hostname);
  if (!port) return Promise.reject(new TypeError(`fetch failed (no route for ${u.hostname})`));
  return fetch(`http://127.0.0.1:${port}${u.pathname}${u.search}`, init);
}

// Stand-in for cloudflare-dns.com: answers from each profile's `dns` field.
async function fakeDoh(url) {
  const name = new URL(url).searchParams.get('name');
  return Response.json({ Answer: (dns.get(name) || []).map((data) => ({ type: 1, data })) });
}
const opts = { fetchImpl: routedFetch, dnsFetch: fakeDoh };

function listen(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      let bytes = 0;
      req.on('data', (c) => (bytes += c.length));
      req.on('end', () => {
        requestLog.push({ host: srv.label, method: req.method, bodyBytes: bytes, contentLength: req.headers['content-length'], ua: req.headers['user-agent'] });
        handler(req, res);
      });
    });
    srv.listen(0, '127.0.0.1', () => resolve(srv));
  });
}

async function profileServer(p) {
  const host = `${p.name}.${DOMAIN}`;
  if (p.dns) dns.set(host, p.dns);
  const send = (res, status, headers, body) => {
    res.statusCode = status;
    for (const [k, v] of Object.entries(headers)) res.setHeader(k, v);
    if (!res.hasHeader('content-type')) res.setHeader('content-type', 'text/html; charset=utf-8');
    res.end(body ?? '<!doctype html><title>t</title><p>hello</p>');
  };
  const servers = [];
  if (p.redirectTo === 'www') {
    const www = await listen((req, res) => send(res, 200, p.headers, p.body));
    www.label = `www.${host}`;
    routes.set(www.label, www.address().port);
    const apex = await listen((req, res) => send(res, 301, { location: `https://www.${host}/` }, ''));
    apex.label = host;
    routes.set(host, apex.address().port);
    servers.push(www, apex);
  } else if (p.redirectTo) {
    const s = await listen((req, res) => send(res, 302, { ...p.headers, location: p.redirectTo }, ''));
    s.label = host;
    routes.set(host, s.address().port);
    servers.push(s);
  } else {
    const s = await listen((req, res) =>
      req.method === 'HEAD' && p.headHeaders
        ? send(res, p.headStatus ?? p.status ?? 200, p.headHeaders, '')
        : send(res, p.status ?? 200, p.headers, p.body),
    );
    s.label = host;
    routes.set(host, s.address().port);
    servers.push(s);
  }
  return { host, servers };
}

// ---------- assertions ----------
const results = [];
function check(name, about, fn) {
  return fn().then(
    (problems) => results.push({ name, about, ok: problems.length === 0, problems, got: problems.got }),
    (err) => results.push({ name, about, ok: false, problems: [`threw: ${err.message}`] }),
  );
}

function compare(res, expect) {
  const p = [];
  const osText = res.details.fingerprint.os ? `${res.details.fingerprint.os.name}${res.details.fingerprint.os.release ? ` ${res.details.fingerprint.os.release}` : ''}` : null;
  if (expect.verdict && res.verdict !== expect.verdict) p.push(`verdict ${res.verdict} != ${expect.verdict}`);
  if ('version' in expect && res.php.version !== expect.version) p.push(`version ${res.php.version} != ${expect.version}`);
  if (expect.fixedIn && res.php.fixedIn !== expect.fixedIn) p.push(`fixedIn ${res.php.fixedIn} != ${expect.fixedIn}`);
  if (expect.os && osText !== expect.os) p.push(`os ${osText} != ${expect.os}`);
  if (expect.sapi && res.php.sapi !== expect.sapi) p.push(`sapi ${res.php.sapi} != ${expect.sapi}`);
  if ('cdn' in expect && res.details.fingerprint.cdn !== expect.cdn) p.push(`cdn ${res.details.fingerprint.cdn} != ${expect.cdn}`);
  if ('webserver' in expect && (res.details.fingerprint.webserver?.raw ?? null) !== expect.webserver) p.push(`webserver ${res.details.fingerprint.webserver?.raw} != ${expect.webserver}`);
  for (const c of expect.context || []) if (!res.context.includes(c)) p.push(`context missing ${c}`);
  if (expect.finding && !res.findings.some((f) => f.id === expect.finding)) p.push(`finding ${expect.finding} missing`);
  if (expect.checks) {
    const got = res.crossCheck.checks.map((c) => c.outcome);
    if (got.join() !== expect.checks.join()) p.push(`checks ${got} != ${expect.checks}`);
  }
  if (expect.final && res.crossCheck.final !== expect.final) p.push(`final ${res.crossCheck.final} != ${expect.final}`);
  if (expect.fallbackRequests) {
    const got = res.details.checks.find((c) => c.name.startsWith('Check 2'))?.note || '';
    for (const r of expect.fallbackRequests) if (!got.includes(r)) p.push(`fallback missing "${r}"`);
  }
  if ('redirects' in expect && res.redirects.length !== expect.redirects) p.push(`redirects ${res.redirects.length} != ${expect.redirects}`);
  if (!res.details.checks.some((c) => c.name.includes('CVE-2026-109618') && c.name.includes('CVE-2026-109619'))) p.push('CVE check step missing');
  p.got = `${res.verdict}${res.php.version ? ` (PHP ${res.php.version})` : ''}`;
  return p;
}

// ---------- real PHP interpreters ----------
function findPhpBinaries() {
  const found = new Map(); // real path -> display path (Homebrew aliases like php and php@8.5 share a binary)
  const add = (p) => existsSync(p) && !found.has(realpathSync(p)) && found.set(realpathSync(p), p);
  for (const root of ['/opt/homebrew/opt', '/usr/local/opt']) {
    if (!existsSync(root)) continue;
    for (const d of readdirSync(root)) if (/^php(@\d+\.\d+)?$/.test(d)) add(`${root}/${d}/bin/php`);
  }
  for (const p of ['/usr/bin/php', '/usr/local/bin/php']) add(p);
  return [...found.values()];
}

async function startPhp(bin, extraArgs = []) {
  const port = await new Promise((r) => {
    const s = http.createServer().listen(0, '127.0.0.1', () => {
      const { port } = s.address();
      s.close(() => r(port));
    });
  });
  const child = spawn(bin, [...extraArgs, '-S', `127.0.0.1:${port}`, '-t', path.join(HERE, 'www')], { stdio: 'ignore' });
  for (let i = 0; i < 50; i++) {
    try {
      const r = await fetch(`http://127.0.0.1:${port}/truth.php`);
      if (r.ok) return { child, port, truth: await r.json() };
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  child.kill();
  throw new Error(`php -S did not start for ${bin}`);
}

// ---------- main ----------
const cleanups = [];
try {
  // 1) Real-world header profiles
  for (const p of PROFILES) {
    const { host, servers } = await profileServer(p);
    cleanups.push(() => servers.forEach((s) => s.close()));
    await check(p.name, p.about, async () => compare(await scan(host, opts), p.expect));
  }

  // 2) 64 KB read cap: CMS marker placed after 1 MB must not be seen
  {
    const big = await listen((req, res) => {
      res.setHeader('content-type', 'text/html');
      res.end('<html>' + 'x'.repeat(1024 * 1024) + '<link href="/wp-content/a.css"></html>');
    });
    big.label = `big.${DOMAIN}`;
    routes.set(big.label, big.address().port);
    cleanups.push(() => big.close());
    await check('read-cap-64kb', 'HTML read stops at 64 KB', async () => {
      const res = await scan(big.label, opts);
      const note = res.details.checks.find((c) => c.name === 'Page sample').note;
      const kb = Number(note.match(/first (\d+) KB/)?.[1]);
      return [...(res.context.includes('wordpress') ? ['read past 64 KB'] : []), ...(kb > 64 ? [`read ${kb} KB`] : [])];
    });
  }

  // 3) Overall timeout: a server that never answers
  {
    const hang = await listen(() => {});
    hang.label = `hang.${DOMAIN}`;
    routes.set(hang.label, hang.address().port);
    cleanups.push(() => hang.closeAllConnections?.() ?? hang.close());
    await check('timeout', 'Unresponsive site fails fast with "timeout"', async () => {
      const t0 = Date.now();
      try {
        await scan(hang.label, { ...opts, timeoutMs: 1500 });
        return ['did not time out'];
      } catch (e) {
        const took = Date.now() - t0;
        return [...(e.code !== 'timeout' ? [`error ${e.code}`] : []), ...(took > 4000 ? [`took ${took} ms`] : [])];
      }
    });
  }

  // 4) Real PHP interpreters (php -S): ground truth from PHP_VERSION
  if (!process.argv.includes('--no-php')) {
    const bins = findPhpBinaries();
    if (!bins.length) results.push({ name: 'real-php', about: 'No PHP binaries on this machine – skipped', ok: true, problems: [], skipped: true });
    for (const bin of bins) {
      for (const hidden of [false, true]) {
        const php = await startPhp(bin, hidden ? ['-d', 'expose_php=0'] : ['-d', 'expose_php=1']);
        cleanups.push(() => php.child.kill());
        const label = `php-${php.truth.version.replace(/\W/g, '-')}${hidden ? '-hidden' : ''}`;
        routes.set(`${label}.${DOMAIN}`, php.port);
        const expected = hidden ? { verdict: 'unknown' } : { verdict: oracle(php.truth.version), version: php.truth.version.match(/^\d+\.\d+\.\d+/)[0] };
        await check(label, `real PHP ${php.truth.version} (${php.truth.sapi}) via ${bin}${hidden ? ', expose_php=Off' : ''}`, async () => {
          const res = await scan(`${label}.${DOMAIN}`, opts);
          const p = compare(res, expected);
          if (!res.php.evidence.some((e) => e.includes('PHPSESSID'))) p.push('PHPSESSID evidence missing');
          if (!hidden) {
            const want = { vulnerable: 'positive', patched: 'negative' }[expected.verdict] ?? 'inconclusive';
            for (const c of res.crossCheck.checks) if (c.outcome !== want) p.push(`${c.id} check ${c.outcome} != ${want}`);
          }
          p.got += ` – expected ${expected.verdict}`;
          return p;
        });
      }
    }
  }

  // 5) Passive-scan promises, over every request any server received
  await check('passive-only', 'Scanner only sent body-less GET/HEAD requests with its own User-Agent', async () => {
    const scannerReqs = requestLog.filter((r) => /PHPChecker\//.test(r.ua || ''));
    const bad = scannerReqs.filter((r) => !['GET', 'HEAD'].includes(r.method) || r.bodyBytes > 0 || (r.contentLength && r.contentLength !== '0'));
    const p = bad.map((r) => `${r.method} with ${r.bodyBytes} body bytes to ${r.host}`);
    if (!scannerReqs.length) p.push('no scanner requests recorded');
    return p;
  });
  await check('no-private-redirect', 'Redirect to 169.254.169.254 was never requested', async () =>
    requestLog.some((r) => /169\.254/.test(r.host || '')) ? ['followed private redirect'] : [],
  );
} finally {
  for (const c of cleanups) {
    try {
      c();
    } catch {
      /* ignore */
    }
  }
}

// ---------- report ----------
let failed = 0;
for (const r of results) {
  if (!r.ok) failed++;
  console.log(`${r.ok ? (r.skipped ? 'SKIP' : 'PASS') : 'FAIL'}  ${r.name.padEnd(30)} ${(r.got || '').padEnd(42)} ${r.about}`);
  for (const p of r.problems) console.log(`      - ${p}`);
}
console.log(`\n${results.length - failed}/${results.length} passed`);
process.exit(failed ? 1 : 0);
