// Production HTTP transport for the Worker.
//
// Cloudflare rewrites response headers on Worker `fetch()` subrequests: every response gets
// `Server: cloudflare`, `CF-RAY` and `CF-Cache-Status`, hiding the target's real web server.
// (X-Powered-By and cookies pass through.) To read genuine headers we speak HTTP/1.1 over a
// raw TCP/TLS socket (`cloudflare:sockets`). Workers may not open sockets to Cloudflare's own
// IP ranges, so for Cloudflare-hosted targets we fall back to `fetch()` and mark the response
// with `x-phpchecker-transport: edge-fetch` so the analyser knows which headers to distrust.

const HEADER_LIMIT = 64 * 1024;
const NULL_BODY = new Set([101, 204, 205, 304]);
export const TRANSPORT_HEADER = 'x-phpchecker-transport';

export function makeEdgeFetch({ maxBody = 64 * 1024 } = {}) {
  return async function edgeFetch(url, init = {}) {
    try {
      return await socketFetch(url, init, maxBody);
    } catch (err) {
      if (init.signal?.aborted) throw init.signal.reason ?? err;
      const res = await fetch(url, init);
      const marked = new Response(NULL_BODY.has(res.status) ? null : res.body, res);
      marked.headers.set(TRANSPORT_HEADER, 'edge-fetch');
      return marked;
    }
  };
}

async function socketFetch(url, { headers = {}, signal } = {}, maxBody) {
  const { connect } = await import('cloudflare:sockets');
  const u = new URL(url);
  const tls = u.protocol === 'https:';
  const port = Number(u.port || (tls ? 443 : 80));
  const sock = connect({ hostname: u.hostname, port }, { secureTransport: tls ? 'on' : 'off', allowHalfOpen: false });
  const abort = () => sock.close().catch(() => {});
  signal?.addEventListener('abort', abort, { once: true });

  try {
    await sock.opened;
    const lines = [`GET ${u.pathname}${u.search} HTTP/1.1`, `Host: ${u.host}`, 'Connection: close', 'Accept-Encoding: identity'];
    for (const [k, v] of Object.entries(headers)) lines.push(`${k}: ${v}`);
    const writer = sock.writable.getWriter();
    await writer.write(new TextEncoder().encode(lines.join('\r\n') + '\r\n\r\n'));
    writer.releaseLock();

    const reader = sock.readable.getReader();
    let buf = new Uint8Array(0);
    const more = async () => {
      const { done, value } = await reader.read();
      if (done) return false;
      buf = concat(buf, value);
      return true;
    };

    // Head (skipping any 1xx interim responses).
    let head;
    for (;;) {
      let end;
      while ((end = indexOfCRLFCRLF(buf)) < 0) {
        if (buf.length > HEADER_LIMIT || !(await more())) throw new Error('bad response head');
      }
      head = new TextDecoder().decode(buf.subarray(0, end));
      buf = buf.subarray(end + 4);
      const code = Number(head.match(/^HTTP\/1\.[01] (\d{3})/)?.[1]);
      if (!code) throw new Error('not HTTP/1.x');
      if (code >= 200 || code === 101) break;
    }

    const [statusLine, ...headerLines] = head.split('\r\n');
    const status = Number(statusLine.split(' ')[1]);
    const h = new Headers();
    for (const line of headerLines) {
      const i = line.indexOf(':');
      if (i > 0) h.append(line.slice(0, i).trim(), line.slice(i + 1).trim());
    }
    h.set(TRANSPORT_HEADER, 'socket');

    // Body: only what the scanner may read (HTML, capped), never for redirects.
    let body = null;
    const wantBody = !NULL_BODY.has(status) && !(status >= 300 && status < 400) && /html/i.test(h.get('content-type') || '');
    if (wantBody) {
      const chunked = /chunked/i.test(h.get('transfer-encoding') || '');
      const length = Number(h.get('content-length'));
      const target = chunked ? maxBody * 2 : Number.isFinite(length) && length >= 0 ? Math.min(length, maxBody) : maxBody;
      while (buf.length < target && (await more()));
      body = chunked ? dechunk(buf).subarray(0, maxBody) : buf.subarray(0, target);
      h.delete('transfer-encoding');
      h.delete('content-length');
    }
    reader.releaseLock();
    sock.close().catch(() => {});
    return new Response(body, { status, headers: h });
  } catch (err) {
    sock.close().catch(() => {});
    throw err;
  } finally {
    signal?.removeEventListener('abort', abort);
  }
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}

function indexOfCRLFCRLF(buf) {
  for (let i = 0; i + 3 < buf.length; i++) {
    if (buf[i] === 13 && buf[i + 1] === 10 && buf[i + 2] === 13 && buf[i + 3] === 10) return i;
  }
  return -1;
}

/** Decode as much of a chunked body as is present. */
export function dechunk(buf) {
  const parts = [];
  let i = 0;
  while (i < buf.length) {
    let eol = i;
    while (eol + 1 < buf.length && !(buf[eol] === 13 && buf[eol + 1] === 10)) eol++;
    if (eol + 1 >= buf.length) break;
    const size = parseInt(new TextDecoder().decode(buf.subarray(i, eol)).split(';')[0].trim(), 16);
    if (!Number.isFinite(size) || size === 0) break;
    const start = eol + 2;
    parts.push(buf.subarray(start, Math.min(start + size, buf.length)));
    i = start + size + 2;
  }
  return parts.reduce(concat, new Uint8Array(0));
}

// Cloudflare's published IPv4 ranges (https://www.cloudflare.com/ips-v4).
const CF_V4 = [
  '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18', '108.162.192.0/18',
  '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17', '162.158.0.0/15', '104.16.0.0/13',
  '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
];
const ip4 = (s) => s.split('.').reduce((n, o) => (n << 8) + Number(o), 0) >>> 0;
export function isCloudflareIp(ip) {
  if (!/^\d+\.\d+\.\d+\.\d+$/.test(ip)) return false;
  const n = ip4(ip);
  return CF_V4.some((cidr) => {
    const [base, bits] = cidr.split('/');
    const mask = bits === '0' ? 0 : (~0 << (32 - Number(bits))) >>> 0;
    return (n & mask) === (ip4(base) & mask);
  });
}

/** true / false via DNS-over-HTTPS, or null if DNS could not be checked. */
export async function resolvesToCloudflare(hostname, { fetchImpl = fetch, timeoutMs = 3000 } = {}) {
  try {
    const r = await fetchImpl(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`, {
      headers: { accept: 'application/dns-json' },
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!r.ok) return null;
    const ips = ((await r.json()).Answer || []).filter((a) => a.type === 1).map((a) => a.data);
    return ips.length ? ips.some(isCloudflareIp) : null;
  } catch {
    return null;
  }
}
