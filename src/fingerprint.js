// Best-effort web server / OS fingerprinting from banners. Everything here is a hint:
// banners can be hidden, rewritten, or reflect backports. Confidence is reported honestly.

const UBUNTU_BY_PHP = { '7.0.33': '16.04', '7.2.24': '18.04', '7.4.3': '20.04', '8.1.2': '22.04', '8.3.6': '24.04' };
const UBUNTU_BY_APACHE = { '2.4.7': '14.04', '2.4.18': '16.04', '2.4.29': '18.04', '2.4.41': '20.04', '2.4.52': '22.04', '2.4.58': '24.04' };
const UBUNTU_BY_NGINX = { '1.4.6': '14.04', '1.10.3': '16.04', '1.14.0': '18.04', '1.18.0': '20.04 or 22.04', '1.24.0': '24.04' };
const DEBIAN_BY_APACHE = { '2.4.38': '10', '2.4.56': '11', '2.4.57': '12', '2.4.62': '12' };
const DEBIAN_BY_NGINX = { '1.14.2': '10', '1.18.0': '11', '1.22.1': '12' };
// Release only – the OS name ("Windows Server") is reported separately.
const IIS_TO_WINDOWS = {
  '10.0': '2016 / 2019 / 2022',
  '8.5': '2012 R2',
  '8.0': '2012',
  '7.5': '2008 R2',
  '7.0': '2008',
};

/** "Apache/2.4.52 (Ubuntu) PHP/8.1.2 OpenSSL/3.0.2" -> {product, version, token, modules} */
export function parseServer(header) {
  if (typeof header !== 'string' || !header.trim()) return null;
  const raw = header.trim().slice(0, 200);
  const m = raw.match(/^([A-Za-z][\w.-]*)(?:\/(\S+))?/);
  if (!m) return { raw, product: raw, version: null, token: null, modules: [] };
  const token = raw.match(/\(([^)]+)\)/)?.[1] ?? null;
  const modules = [...raw.matchAll(/\b([A-Za-z_][\w.-]*)\/(\d[\w.~+-]*)/g)].slice(1).map((x) => `${x[1]}/${x[2]}`);
  return { raw, product: m[1], version: m[2] ?? null, token, modules };
}

/** Returns {name, release, confidence, basis} or null. */
export function fingerprintOS({ server, phpBanner } = {}) {
  const s = parseServer(server);
  const php = phpBanner || '';

  // "ubuntu0.24.04.5" (Ubuntu archive) or "+ubuntu22.04.1+deb.sury.org" (Ondřej Surý PPA)
  let m = php.match(/ubuntu0?\.?(\d\d\.\d\d)/i);
  if (m) return { name: 'Ubuntu', release: m[1], confidence: 'high', basis: 'PHP package version string' };

  if (/ubuntu/i.test(php) || /ubuntu/i.test(s?.token || '')) {
    const phpVer = php.match(/(\d+\.\d+\.\d+)/)?.[1];
    if (phpVer && UBUNTU_BY_PHP[phpVer]) return { name: 'Ubuntu', release: UBUNTU_BY_PHP[phpVer], confidence: 'medium', basis: `PHP ${phpVer} is the stock Ubuntu ${UBUNTU_BY_PHP[phpVer]} package` };
    const rel = s && (s.product === 'Apache' ? UBUNTU_BY_APACHE[s.version] : /nginx/i.test(s.product) ? UBUNTU_BY_NGINX[s.version] : null);
    if (rel) return { name: 'Ubuntu', release: rel, confidence: 'medium', basis: `${s.product} ${s.version} is the stock Ubuntu ${rel} package` };
    return { name: 'Ubuntu', release: null, confidence: 'low', basis: 'Ubuntu token in banner' };
  }

  m = php.match(/deb(\d+)u\d+|[+~]deb(\d+)|debian(\d+)/i);
  if (m) return { name: 'Debian', release: m[1] || m[2] || m[3], confidence: 'high', basis: 'PHP package version string' };
  if (/debian/i.test(s?.token || '')) {
    const rel = s.product === 'Apache' ? DEBIAN_BY_APACHE[s.version] : /nginx/i.test(s.product) ? DEBIAN_BY_NGINX[s.version] : null;
    return rel
      ? { name: 'Debian', release: rel, confidence: 'medium', basis: `${s.product} ${s.version} is the stock Debian ${rel} package` }
      : { name: 'Debian', release: null, confidence: 'low', basis: 'Debian token in banner' };
  }

  m = php.match(/\.el(\d+)/i);
  if (m) return { name: 'RHEL-family (RHEL / Alma / Rocky / CentOS)', release: m[1], confidence: 'high', basis: 'PHP package version string' };
  const t = s?.token || '';
  if (/red hat|rhel/i.test(t)) return { name: 'Red Hat Enterprise Linux', release: null, confidence: 'low', basis: 'Banner token' };
  if (/centos/i.test(t)) return { name: 'CentOS', release: null, confidence: 'low', basis: 'Banner token' };
  if (/rocky/i.test(t)) return { name: 'Rocky Linux', release: null, confidence: 'low', basis: 'Banner token' };
  if (/alma/i.test(t)) return { name: 'AlmaLinux', release: null, confidence: 'low', basis: 'Banner token' };
  if (/fedora/i.test(t)) return { name: 'Fedora', release: null, confidence: 'low', basis: 'Banner token' };
  if (/amazon|amzn/i.test(t + php)) return { name: 'Amazon Linux', release: null, confidence: 'low', basis: 'Banner token' };
  if (/win(32|64)/i.test(t)) return { name: 'Windows', release: null, confidence: 'low', basis: 'Banner token' };
  if (/alpine/i.test(php)) return { name: 'Alpine Linux', release: null, confidence: 'low', basis: 'PHP package version string' };

  if (s && /^microsoft-iis$/i.test(s.product)) {
    return { name: 'Windows Server', release: IIS_TO_WINDOWS[s.version] ?? null, confidence: IIS_TO_WINDOWS[s.version] ? 'medium' : 'low', basis: `IIS ${s.version ?? ''} ships with that Windows release`.trim() };
  }
  return null;
}
