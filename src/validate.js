export class ScanError extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
}

const ALLOWED_PORTS = new Set(['', '80', '443', '8080', '8443']);
const BLOCKED_SUFFIXES = ['.localhost', '.local', '.internal', '.lan', '.home', '.corp', '.intranet', '.test', '.invalid', '.example', '.arpa'];
// Public wildcard-DNS services that resolve names to arbitrary (often private) IPs.
// Cloudflare's egress cannot reach private networks anyway; this also protects `wrangler dev`.
const REBINDING_DOMAINS = ['nip.io', 'sslip.io', 'xip.io', 'localtest.me', 'lvh.me', 'vcap.me', 'lacolhost.com', 'localh.st', 'traefik.me', 'readme.localtest.me'];

/**
 * Normalise user input into a safe public http(s) URL or throw ScanError.
 * Rejects IP literals, single-label hosts, internal suffixes, credentials and unusual ports.
 */
export function normalizeTarget(input) {
  if (typeof input !== 'string' || !input.trim()) throw new ScanError('bad_url', 'Enter a domain or URL.');
  let raw = input.trim();
  if (raw.length > 2048) throw new ScanError('bad_url', 'That URL is too long.');
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(raw)) raw = `https://${raw}`;

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new ScanError('bad_url', 'That does not look like a valid URL.');
  }
  return assertPublic(url);
}

export function assertPublic(url) {
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new ScanError('bad_scheme', 'Only http and https targets can be scanned.');
  }
  if (url.username || url.password) throw new ScanError('bad_url', 'URLs with credentials are not allowed.');
  if (!ALLOWED_PORTS.has(url.port)) throw new ScanError('bad_port', 'Only ports 80, 443, 8080 and 8443 are allowed.');

  const host = url.hostname.toLowerCase().replace(/\.$/, '');
  if (host.startsWith('[') || host.includes(':')) throw new ScanError('ip_literal', 'IP addresses are not scannable; use a domain name.');
  if (/^\d+(\.\d+){0,3}$/.test(host) || /^0x[0-9a-f]+$/i.test(host)) {
    throw new ScanError('ip_literal', 'IP addresses are not scannable; use a domain name.');
  }
  if (!host.includes('.') || host === 'localhost') throw new ScanError('internal_host', 'Only public domain names can be scanned.');
  if (BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) throw new ScanError('internal_host', 'Only public domain names can be scanned.');
  if (REBINDING_DOMAINS.some((d) => host === d || host.endsWith(`.${d}`))) {
    throw new ScanError('internal_host', 'Wildcard-DNS hostnames that map to IP addresses are not scannable.');
  }
  if (!/^[a-z0-9.-]+$/.test(host)) throw new ScanError('bad_url', 'Unsupported characters in hostname.');
  url.hash = '';
  return url;
}
