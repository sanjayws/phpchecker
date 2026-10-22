import { renderPage } from './ui.js';
import { getResources } from './resources.js';
import { checkVersion, scan } from './scanner.js';
import { ScanError } from './validate.js';
import { makeEdgeFetch } from './transport.js';

const edgeFetch = makeEdgeFetch();

const LIMIT = 10;
const WINDOW_MS = 60_000;
const buckets = new Map(); // per-isolate fallback when the ratelimit binding is absent

const API_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};
// Read-only data endpoints are open to other sites; /api/scan deliberately is not, so
// third-party pages can't make visitors' browsers trigger scans attributed to them.
const CORS = { 'access-control-allow-origin': '*' };

function json(body, status = 200, extra = {}) {
  return new Response(JSON.stringify(body), { status, headers: { ...API_HEADERS, ...extra } });
}

async function allowed(request, env) {
  const key = request.headers.get('cf-connecting-ip') || 'anonymous';
  if (env?.SCAN_LIMITER?.limit) {
    const { success } = await env.SCAN_LIMITER.limit({ key });
    return success;
  }
  const now = Date.now();
  const b = buckets.get(key);
  if (!b || now > b.reset) {
    if (buckets.size > 5000) buckets.clear();
    buckets.set(key, { count: 1, reset: now + WINDOW_MS });
    return true;
  }
  return ++b.count <= LIMIT;
}

/**
 * Audit log – the only thing this app records. One JSON line per scan request, kept by
 * Workers Logs (see wrangler.toml [observability]) for safety and audit-trail purposes:
 * time, requester IP, country, user agent, target hostname (never path or query) and
 * outcome. No cookies, analytics or other tracking. The UI states this.
 */
function logEvent(request, fields) {
  console.log(
    JSON.stringify({
      event: 'scan',
      ts: new Date().toISOString(),
      ip: request.headers.get('cf-connecting-ip') || null,
      country: request.cf?.country || null,
      ua: (request.headers.get('user-agent') || '').slice(0, 160),
      ...fields,
    }),
  );
}

function targetHost(raw) {
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`).hostname.slice(0, 253);
  } catch {
    return null;
  }
}

function htmlResponse() {
  const nonce = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(16))));
  const csp = [
    "default-src 'none'",
    `script-src 'nonce-${nonce}'`,
    `style-src 'nonce-${nonce}'`,
    "connect-src 'self'",
    "img-src 'self' data:",
    "base-uri 'none'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ');
  return new Response(renderPage(nonce), {
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'content-security-policy': csp,
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'cache-control': 'no-cache',
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      const open = url.pathname === '/api/resources' || url.pathname === '/api/version';
      return new Response(null, { status: 204, headers: open ? { ...CORS, 'access-control-allow-methods': 'GET, OPTIONS' } : {} });
    }
    if (request.method !== 'GET' && request.method !== 'HEAD') return json({ error: 'method_not_allowed' }, 405);

    let logCtx = null;
    try {
      switch (url.pathname) {
        case '/':
          return htmlResponse();
        case '/healthz':
          return json({ ok: true });
        case '/api/resources':
          return json(getResources(), 200, { ...CORS, 'cache-control': 'public, max-age=300' });
        case '/api/version':
          // Pure computation on the given string: no network request, nothing logged.
          return json(checkVersion(url.searchParams.get('v')), 200, CORS);
        case '/api/scan': {
          const raw = url.searchParams.get('url') ?? '';
          logCtx = { kind: 'scan', target: targetHost(raw) };
          if (request.headers.get('sec-fetch-site') === 'cross-site') {
            throw new ScanError('cross_site', 'Scans can only be started from this site or a non-browser client.', 403);
          }
          if (url.searchParams.get('authorized') !== '1') {
            throw new ScanError('consent_required', 'Confirm that you own this site or are authorised to test it.');
          }
          if (!(await allowed(request, env))) {
            logEvent(request, { ...logCtx, outcome: 'rate_limited' });
            return json({ error: 'rate_limited', message: 'Too many scans. Try again in a minute.' }, 429, { 'retry-after': '60' });
          }
          const result = await scan(raw, { fetchImpl: edgeFetch });
          logEvent(request, {
            ...logCtx,
            outcome: 'ok',
            verdict: result.verdict,
            phpVersion: result.php.version,
            webserver: result.details.fingerprint.webserver?.raw ?? null,
            httpStatus: result.httpStatus,
          });
          return json(result);
        }
        default:
          return json({ error: 'not_found' }, 404);
      }
    } catch (err) {
      if (err instanceof ScanError) {
        if (logCtx) logEvent(request, { ...logCtx, outcome: 'error', error: err.code });
        return json({ error: err.code, message: err.message }, err.status);
      }
      if (logCtx) logEvent(request, { ...logCtx, outcome: 'error', error: 'internal' });
      return json({ error: 'internal', message: 'Something went wrong.' }, 500);
    }
  },
};
