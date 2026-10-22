import { ADVISORY } from './advisory.js';
import { assessVersion, detectBackport, extractPhpToken, parseVersion, verdictFor } from './version.js';
import { fingerprintOS, parseServer } from './fingerprint.js';
import { assertPublic, normalizeTarget, ScanError } from './validate.js';
import { PROJECT } from './project.js';
import { TRANSPORT_HEADER, resolvesToCloudflare } from './transport.js';

const MAX_HOPS = 3;
const MAX_BODY_BYTES = 64 * 1024;
const TOTAL_TIMEOUT_MS = 10_000;
const USER_AGENT = `${PROJECT.name}/1.0 (passive version check; +${PROJECT.repo})`;

const CMS_SIGNATURES = [
  { id: 'wordpress', name: 'WordPress', re: /wp-content\/|wp-includes\/|content="WordPress/i },
  { id: 'drupal', name: 'Drupal', re: /content="Drupal|\/sites\/default\/files|drupal-settings-json/i },
  { id: 'joomla', name: 'Joomla', re: /content="Joomla|\/media\/system\/js\//i },
  { id: 'magento', name: 'Magento', re: /\/static\/version\d+\/|Mage\.Cookies|mage-cache-storage/i },
  { id: 'mediawiki', name: 'MediaWiki', re: /content="MediaWiki/i },
  { id: 'phpmyadmin', name: 'phpMyAdmin', re: /<title>[^<]*phpMyAdmin|pma_navigation|phpmyadmin\.css/i },
];

// Headers Cloudflare stamps onto every Worker fetch() subrequest response (see transport.js).
const EDGE_STAMPED = ['server', 'cf-ray', 'cf-cache-status'];

// Header fingerprints of CDNs / reverse proxies. When present, origin banners are often stripped.
const CDN_SIGNATURES = [
  { name: 'Cloudflare', test: (h, s) => h.has('cf-ray') || /^cloudflare/i.test(s) },
  { name: 'Fastly', test: (h) => h.has('x-fastly-request-id') || /fastly/i.test(h.get('x-served-by') || '') },
  { name: 'Akamai', test: (h, s) => /akamai/i.test(s) || h.has('x-akamai-transformed') },
  { name: 'Amazon CloudFront', test: (h) => h.has('x-amz-cf-id') || /cloudfront/i.test(h.get('via') || '') },
  { name: 'Bunny CDN', test: (h, s) => /^bunnycdn/i.test(s) || h.has('cdn-pullzone') },
  { name: 'Sucuri', test: (h, s) => h.has('x-sucuri-id') || /sucuri/i.test(s) },
  { name: 'Imperva', test: (h) => h.has('x-iinfo') || /incapsula|imperva/i.test(h.get('x-cdn') || '') },
  { name: 'Vercel', test: (h) => h.has('x-vercel-id') },
  { name: 'Netlify', test: (h) => h.has('x-nf-request-id') },
  { name: 'Azure Front Door', test: (h) => h.has('x-azure-ref') },
  { name: 'Google Cloud CDN', test: (h) => /\bgoogle\b/i.test(h.get('via') || '') },
];

/**
 * Passive scan: one GET per hop, no payloads. `fetchImpl` is injectable for tests and
 * for the validation harness (validation/validate.mjs).
 */
export async function scan(input, { fetchImpl = fetch, dnsFetch = fetch, timeoutMs = TOTAL_TIMEOUT_MS } = {}) {
  let url = normalizeTarget(input);
  const hops = [];
  const notes = [];
  let body = '';
  const startedAt = Date.now();
  // One budget for the whole scan (all hops + body read), not per hop.
  const signal = AbortSignal.timeout(timeoutMs);

  for (let i = 0; i <= MAX_HOPS; i++) {
    let res;
    try {
      res = await fetchImpl(url.toString(), {
        method: 'GET',
        redirect: 'manual',
        headers: { 'user-agent': USER_AGENT, accept: 'text/html,*/*;q=0.5' },
        signal,
      });
    } catch (err) {
      if (hops.length) {
        notes.push({ id: 'redirect-failed', text: `Could not load the redirect target ${url.hostname}; showing results for the previous response.` });
        break;
      }
      const timedOut = err?.name === 'TimeoutError' || err?.name === 'AbortError';
      throw new ScanError(
        timedOut ? 'timeout' : 'unreachable',
        timedOut ? 'The site took too long to respond.' : 'Could not connect to that site.',
        502,
      );
    }

    hops.push({ url: url.toString(), status: res.status, headers: res.headers, transport: res.headers.get(TRANSPORT_HEADER) || 'direct' });

    const location = res.headers.get('location');
    if (res.status >= 300 && res.status < 400 && location) {
      await res.body?.cancel().catch(() => {});
      if (i === MAX_HOPS) {
        notes.push({ id: 'redirect-limit', text: `Stopped after ${MAX_HOPS} redirects; results are for the last redirect response.` });
        break;
      }
      let next;
      try {
        next = assertPublic(new URL(location, url));
      } catch {
        // Never follow a redirect into a private/odd address, but keep what we learned so far.
        notes.push({ id: 'redirect-blocked', text: `The site redirects to a non-public or unsupported address, which ${PROJECT.name} does not follow.` });
        break;
      }
      url = next;
      continue;
    }

    if ((res.headers.get('content-type') || '').includes('html')) body = await readLimited(res, MAX_BODY_BYTES);
    else await res.body?.cancel().catch(() => {});
    break;
  }

  // Edge-stamped headers can't tell us whether the target itself is on Cloudflare; DNS can.
  const finalHop = hops[hops.length - 1];
  const cfDns = finalHop.transport === 'edge-fetch' ? await resolvesToCloudflare(new URL(finalHop.url).hostname, { fetchImpl: dnsFetch }) : null;

  return analyze(input, hops, body, { elapsedMs: Date.now() - startedAt, bodyChars: body.length, notes, cfDns });
}

async function readLimited(res, max) {
  if (!res.body) return '';
  const reader = res.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    while (total < max) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
      total += value.length;
    }
  } catch {
    /* partial body is fine */
  } finally {
    reader.cancel().catch(() => {});
  }
  const buf = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    buf.set(c, off);
    off += c.length;
  }
  return new TextDecoder().decode(buf.subarray(0, max));
}

const TRANSPORT_NOTES = {
  socket: 'Direct TLS/TCP connection from the Worker – headers are exactly what the site sent.',
  'edge-fetch':
    "Cloudflare-hosted site (Workers can't open direct sockets to Cloudflare), so the request went through Cloudflare's fetch, which replaces the Server header. The origin web server can't be seen; PHP headers and cookies are unaffected.",
  direct: 'Fetched directly.',
};

function withoutEdgeStamps(headers) {
  const h = new Headers(headers);
  for (const k of EDGE_STAMPED) h.delete(k);
  return h;
}

/** Pure function over collected hops so it can be unit-tested without network. */
export function analyze(input, hops, body = '', meta = {}) {
  const final = hops[hops.length - 1];
  const evidence = [];
  const findings = [];
  const context = new Set();

  let poweredBy = null;
  let server = null;
  let versionBanner = null;
  const cookies = [];
  let cdn = null;

  for (const hop of [...hops].reverse()) {
    // Final response first: it is the one that actually served the page.
    const h = hop.transport === 'edge-fetch' ? withoutEdgeStamps(hop.headers) : hop.headers;
    const xpb = h.get('x-powered-by');
    const srv = h.get('server');
    if (xpb && /php/i.test(xpb) && !poweredBy) poweredBy = xpb;
    if (srv && !server) server = srv;
    if (!cdn) cdn = CDN_SIGNATURES.find((c) => c.test(h, srv || ''))?.name ?? null;
    if (!cdn && hop.transport === 'edge-fetch' && meta.cfDns) cdn = 'Cloudflare';
    const setCookie = typeof h.getSetCookie === 'function' ? h.getSetCookie() : [h.get('set-cookie')].filter(Boolean);
    for (const c of setCookie) cookies.push(c.split(';')[0].split('=')[0].trim());
  }

  let phpToken = null;
  if (poweredBy) {
    evidence.push(`X-Powered-By: ${poweredBy}`);
    phpToken = extractPhpToken(poweredBy);
    if (phpToken) versionBanner = poweredBy;
  }
  if (server && /php/i.test(server)) {
    evidence.push(`Server: ${server}`);
    if (!phpToken) {
      phpToken = extractPhpToken(server);
      if (phpToken) versionBanner = server;
    }
  }
  const sessionCookie = cookies.find((c) => c.toUpperCase() === 'PHPSESSID');
  if (sessionCookie) evidence.push('Set-Cookie: PHPSESSID (PHP session cookie)');
  if (/\.php(\?|$)/i.test(final.url)) evidence.push(`URL ends in .php (${new URL(final.url).pathname})`);
  if (cookies.some((c) => /^laravel_session$/i.test(c))) evidence.push('Set-Cookie: laravel_session (Laravel)');

  const cms = CMS_SIGNATURES.filter((s) => s.re.test(body) || s.re.test(final.headers.get('x-generator') || ''));
  if (!cms.some((c) => c.id === 'wordpress') && /wp-json|api\.w\.org/i.test(final.headers.get('link') || '')) {
    cms.unshift(CMS_SIGNATURES[0]);
  }
  for (const c of cms) {
    evidence.push(`${c.name} markers in page`);
    context.add(c.id);
  }

  const phpDetected = evidence.length > 0;
  const backport = detectBackport(phpToken, server);
  const v = phpToken ? parseVersion(phpToken) : null;
  const assessment = v ? assessVersion(v) : null;

  let sapi = 'unknown';
  if (phpDetected && server) {
    if (/apache/i.test(server) && /php\/?\s*\d/i.test(server)) sapi = 'mod_php (Apache module)';
    else if (/nginx|openresty/i.test(server)) sapi = 'likely PHP-FPM (behind nginx)';
    else if (/litespeed/i.test(server)) sapi = 'likely LSAPI (LiteSpeed)';
    else if (/microsoft-iis/i.test(server)) sapi = 'likely FastCGI (IIS)';
  }

  let verdict;
  let headline;
  let detail;
  if (assessment) {
    verdict = verdictFor(assessment, backport);
    headline = {
      vulnerable: 'Likely vulnerable',
      verify: 'Needs verification',
      patched: 'Patched version reported',
    }[verdict];
    detail = assessment.summary;
    if (backport && verdict === 'verify') {
      detail += ` This build comes from ${backport}, and vendors often backport fixes without changing the version number, so check the package changelog for ${ADVISORY.cves.map((c) => c.id).join(' and ')}.`;
    }
    if (verdict === 'patched') detail += ' Banners can be spoofed or stale; confirm workers were restarted after the upgrade.';
  } else if (phpDetected) {
    verdict = 'unknown';
    headline = 'PHP detected, version hidden';
    detail = 'The site runs PHP but does not disclose its version, so exposure cannot be determined from outside. Hiding the version is good hygiene, but it is not a fix: check the version on the server itself.';
  } else {
    verdict = 'no-php';
    headline = 'No PHP signals found';
    detail = 'Nothing in the headers or HTML of this page points to PHP. Other paths or sibling hosts may still run PHP, so this is not proof of safety.';
    if (cdn) detail += ` The site is behind ${cdn}, which can hide the origin server's headers.`;
  }

  if (phpDetected) context.add('php');
  if (assessment) context.add(verdict);
  if (assessment?.status === 'vulnerable_eol' || assessment?.status === 'unlisted') context.add('eol');
  if (!assessment && phpDetected) context.add('version-hidden');
  if (backport) context.add('distro');
  if (cdn === 'Cloudflare') context.add('cloudflare');
  if (sessionCookie) context.add('session');
  if (sapi.startsWith('mod_php')) context.add('mod_php');
  if (sapi.includes('FPM')) context.add('fpm');

  for (const n of meta.notes || []) findings.push({ id: n.id, severity: 'info', title: 'Scan was limited', detail: n.text });
  if (final.status >= 400) {
    const challenged = final.headers.get('cf-mitigated') === 'challenge';
    findings.push({
      id: 'http-error',
      severity: 'info',
      title: `The site answered HTTP ${final.status}`,
      detail: challenged
        ? 'A bot challenge blocked the scanner, so headers from the real application were not visible. Results are incomplete.'
        : 'Error pages and WAF blocks can hide application headers, so results may be incomplete.',
    });
  }
  if (versionBanner) {
    findings.push({
      id: 'version-disclosed',
      severity: 'low',
      title: 'PHP version is disclosed to the internet',
      detail: `${versionBanner} is sent in response headers. Set expose_php = Off and strip version tokens (ServerTokens Prod, server_tokens off) so scanners and attackers can't target you by version.`,
    });
  }
  if (sessionCookie) {
    findings.push({
      id: 'php-sessions',
      severity: 'info',
      title: 'PHP sessions are in use',
      detail: 'A PHPSESSID cookie was issued. Several attack chains in the advisory depend on session handling, so apply the session.* hardening in the help below.',
    });
  }
  if (cdn === 'Cloudflare') {
    findings.push({
      id: 'cloudflare',
      severity: 'info',
      title: 'Traffic passes through Cloudflare',
      detail: 'Cloudflare says its managed WAF rules cover these CVEs. That reduces exposure but does not replace patching PHP, and only helps if the origin cannot be reached directly.',
    });
  }
  if (sapi !== 'unknown') {
    findings.push({ id: 'sapi', severity: 'info', title: `Likely SAPI: ${sapi}`, detail: 'Guessed from the Server header. Some attack chains differ between mod_php and PHP-FPM.' });
  }

  const serverInfo = parseServer(server);
  const os = fingerprintOS({ server, phpBanner: phpToken });
  const cveList = ADVISORY.cves.map((c) => c.id).join(' and ');
  const checks = [
    { name: 'Target validation', status: 'ok', note: 'Public hostname and allowed port. IP literals, localhost, internal names and wildcard-DNS hosts are refused; every redirect is re-checked.' },
    {
      name: 'HTTP request',
      status: 'ok',
      note: `One GET request per hop (no body sent)${final.transport === 'socket' ? ' over a direct TLS/TCP connection' : final.transport === 'edge-fetch' ? " via Cloudflare's fetch (Cloudflare-hosted site)" : ''}. Final response: HTTP ${final.status}${meta.elapsedMs != null ? ` in ${meta.elapsedMs} ms` : ''}; ${hops.length - 1} redirect(s) followed (max ${MAX_HOPS}).`,
    },
    {
      name: 'Response headers',
      status: server || poweredBy ? 'found' : 'none',
      note: `Inspected Server, X-Powered-By, Set-Cookie, Link, X-Generator and CDN headers. ${server ? `Server: ${server}. ` : 'No Server header. '}${poweredBy ? `X-Powered-By: ${poweredBy}.` : 'No PHP X-Powered-By header.'}`,
    },
    {
      name: 'PHP version banner',
      status: phpToken ? 'found' : 'none',
      note: phpToken ? `Read PHP version "${phpToken}" from "${versionBanner}".` : 'The site does not disclose a PHP version in its headers.',
    },
    {
      name: 'Page sample',
      status: meta.bodyChars ? (cms.length ? 'found' : 'none') : 'skipped',
      note: meta.bodyChars
        ? `Read the first ${Math.max(1, Math.round(meta.bodyChars / 1024))} KB of HTML looking for CMS markers (WordPress, Drupal, Joomla, Magento, MediaWiki, phpMyAdmin).${cms.length ? ` Found: ${cms.map((c) => c.name).join(', ')}.` : ''}`
        : 'Response was not HTML, so the page was not read.',
    },
    {
      name: 'Web server & OS fingerprint',
      status: serverInfo || os ? 'found' : 'none',
      note:
        `${serverInfo ? `Web server: ${serverInfo.product}${serverInfo.version ? ` ${serverInfo.version}` : ''}. ` : final.transport === 'edge-fetch' ? 'Web server hidden (Cloudflare-hosted site, Server header replaced in transit). ' : 'Web server not disclosed. '}` +
        (cdn ? `Served through ${cdn}. ` : '') +
        (os
          ? `OS hint: ${os.name}${os.release ? ` ${os.release}` : ''} (${os.confidence} confidence – ${os.basis}).`
          : 'No operating-system hints in the banners (this is common and fine).'),
    },
    {
      name: `Check for ${cveList}`,
      status: assessment ? 'ok' : 'skipped',
      note: assessment
        ? `Compared PHP ${assessment.version} with the affected range (5.4.0 – ${ADVISORY.lastAffected}) and fixed releases (${Object.entries(ADVISORY.fixed).map(([b, p]) => `${b}.${p}`).join(', ')}): ${assessment.summary}`
        : 'Not possible – no PHP version was disclosed.',
    },
    {
      name: 'Exploit attempts',
      status: 'skipped',
      note: 'Never performed. No uploads, session-upload markers or payloads are sent; php.ini values (e.g. session.upload_progress) cannot be seen remotely.',
    },
  ];

  return {
    details: {
      checks,
      fingerprint: {
        webserver: serverInfo
          ? { name: serverInfo.product, version: serverInfo.version, raw: serverInfo.raw, modules: serverInfo.modules, behindCdn: cdn }
          : null,
        php: { version: assessment?.version ?? null, banner: phpToken, sapi },
        os,
        cdn,
      },
      request: {
        httpStatus: final.status,
        redirects: hops.length - 1,
        elapsedMs: meta.elapsedMs ?? null,
        userAgent: USER_AGENT,
        transport: final.transport,
        transportNote: TRANSPORT_NOTES[final.transport],
      },
    },
    target: final.url,
    requested: input,
    scannedAt: new Date().toISOString(),
    verdict,
    headline,
    detail,
    php: {
      detected: phpDetected,
      version: assessment?.version ?? null,
      fixedIn: assessment?.fixedIn ?? null,
      status: assessment?.status ?? null,
      sapi,
      distro: backport,
      cms: cms.map((c) => c.name),
      evidence,
    },
    redirects: hops.slice(0, -1).map((h) => ({ url: h.url, status: h.status })),
    httpStatus: final.status,
    findings,
    context: [...context],
    advisory: { cves: ADVISORY.cves.map((c) => c.id), fixed: ADVISORY.fixed },
  };
}

/** Version-only check (API: /api/version). */
export function checkVersion(input) {
  const raw = String(input ?? '').trim().slice(0, 120);
  const token = extractPhpToken(raw) ?? raw;
  const v = parseVersion(token);
  if (!v) throw new ScanError('bad_version', 'Enter a PHP version such as 8.3.30.');
  const assessment = assessVersion(v);
  const backport = detectBackport(token, null);
  const verdict = verdictFor(assessment, backport);
  const context = ['php', verdict];
  if (assessment.status === 'vulnerable_eol' || assessment.status === 'unlisted') context.push('eol');
  if (backport) context.push('distro');
  const os = fingerprintOS({ phpBanner: token });
  return {
    details: {
      checks: [
        { name: 'Input parsing', status: 'ok', note: `Read PHP version ${assessment.version} from "${raw}".` },
        { name: `Check for ${ADVISORY.cves.map((c) => c.id).join(' and ')}`, status: 'ok', note: assessment.summary },
        { name: 'Operating-system hint', status: os ? 'found' : 'none', note: os ? `${os.name}${os.release ? ` ${os.release}` : ''} (${os.confidence} confidence – ${os.basis}).` : 'The version string carries no distro information.' },
        { name: 'Network request', status: 'skipped', note: 'None – this check is done purely on the version string you entered.' },
      ],
      fingerprint: { webserver: null, php: { version: assessment.version, banner: token, sapi: 'unknown' }, os, cdn: null },
      request: null,
    },
    requested: raw,
    scannedAt: new Date().toISOString(),
    verdict,
    headline: { vulnerable: 'Vulnerable version', verify: 'Needs verification', patched: 'Patched version' }[verdict],
    detail: assessment.summary + (backport ? ` This build comes from ${backport}; check its changelog for the backported fix.` : ''),
    php: { detected: true, version: assessment.version, fixedIn: assessment.fixedIn, status: assessment.status, sapi: 'unknown', distro: backport, cms: [], evidence: [] },
    findings: [],
    context,
    advisory: { cves: ADVISORY.cves.map((c) => c.id), fixed: ADVISORY.fixed },
  };
}
