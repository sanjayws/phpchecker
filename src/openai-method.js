// Re-implementation of the detection method of OpenAI's php2shell-checker
//   https://github.com/openai/php2shell-checker   (Apache-2.0, © OpenAI)
// (skills/phpcheck-url/scripts/phpcheck.js, v1.0.0, cutoffs "as of 2026-10-20").
// No source is copied; the method and its version table are re-implemented so PHPChecker can
// run it as an independent second opinion on every scan. See THIRD_PARTY_NOTICES.md.
//
// Method: HEAD the URL exactly as given (GET only if the server answers 405/501), do not
// follow redirects, collect `Server` and `X-Powered-By`, and test every `PHP[ /]<version>`
// token against a per-branch "vulnerable through" patch table. A vulnerable or unrecognised
// banner is never hidden by a later "ok" one.

import { TRANSPORT_HEADER } from './transport.js';

export const OPENAI_VULNERABLE_THROUGH = {
  '5.4': 45, '5.5': 38, '5.6': 40,
  '7.0': 33, '7.1': 33, '7.2': 34, '7.3': 33, '7.4': 33,
  '8.0': 30, '8.1': 34, '8.2': 34, '8.3': 35, '8.4': 26, '8.5': 11,
};

/** 'ok' | 'vulnerable' | 'unknown' – same rules as the upstream patchStatus(). */
export function openaiPatchStatus(version) {
  const m = /^(\d+)\.(\d+)\.(\d+)([-+~].*)?$/.exec(version || '');
  if (!m) return 'unknown';
  const cutoff = OPENAI_VULNERABLE_THROUGH[`${Number(m[1])}.${Number(m[2])}`];
  if (cutoff === undefined) return 'unknown';
  if (Number(m[3]) <= cutoff) return 'vulnerable';
  // A development build of the next patch is not evidence of a stable fix.
  if (/(?:^|[-+~.])(?:dev|alpha|beta|rc)/i.test(m[4] || '')) return 'unknown';
  return 'ok';
}

/** Pick the version exactly as upstream does over a list of banner strings. */
export function openaiPickVersion(bannerTexts) {
  let version = null;
  let status = 'unknown';
  let source = null;
  for (const { name, value } of bannerTexts) {
    for (const m of value.matchAll(/\bPHP[ /]([^\s,;)]+)/gi)) {
      const candidate = openaiPatchStatus(m[1]);
      // Do not let an OK banner hide a vulnerable or unrecognised PHP version.
      if (version === null || candidate === 'vulnerable' || status === 'ok') {
        version = m[1];
        status = candidate;
        source = `${name}: ${value}`;
      }
      if (status === 'vulnerable') return { version, status, source };
    }
  }
  return { version, status, source };
}

/**
 * Run the upstream request sequence against `url` and classify the result.
 * `stripEdge(headers)` removes Cloudflare-stamped headers for edge-fetch responses.
 */
export async function runOpenaiCheck(url, { fetchImpl, signal, userAgent, stripEdge }) {
  const requests = [];
  const banners = [];
  let error = null;
  try {
    for (const method of ['HEAD', 'GET']) {
      const res = await fetchImpl(url.toString(), { method, redirect: 'manual', headers: { 'user-agent': userAgent }, signal });
      await res.body?.cancel().catch(() => {});
      requests.push({ method, status: res.status, url: url.toString() });
      const h = res.headers.get(TRANSPORT_HEADER) === 'edge-fetch' ? stripEdge(res.headers) : res.headers;
      for (const name of ['server', 'x-powered-by']) {
        const value = h.get(name);
        if (value) banners.push({ name: name === 'server' ? 'Server' : 'X-Powered-By', value });
      }
      if (![405, 501].includes(res.status)) break;
    }
  } catch (err) {
    error = err?.name === 'TimeoutError' || err?.name === 'AbortError' ? 'timed out' : 'request failed';
  }
  const picked = openaiPickVersion(banners);
  return { ...picked, requests, error };
}
