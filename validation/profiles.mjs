// Real-world response header profiles, replayed over real HTTP by validate.mjs.
// Banner formats are the ones these stacks actually emit (distro package version
// strings, ServerTokens Full, Plesk/IIS multi-value X-Powered-By, CDN headers…).
// `expect` is written by hand from the advisory, not computed by the scanner.

export const PROFILES = [
  {
    name: 'ubuntu-2204-apache-modphp',
    about: 'Ubuntu 22.04 archive PHP behind Apache (distro may backport)',
    headers: { server: 'Apache/2.4.52 (Ubuntu)', 'x-powered-by': 'PHP/8.1.2-1ubuntu2.20', 'set-cookie': 'PHPSESSID=0123456789abcdef; path=/' },
    expect: { verdict: 'verify', version: '8.1.2', os: 'Ubuntu 22.04' },
  },
  {
    name: 'ubuntu-2404-apache',
    about: 'Ubuntu 24.04 archive PHP 8.3.6',
    headers: { server: 'Apache/2.4.58 (Ubuntu)', 'x-powered-by': 'PHP/8.3.6-0ubuntu0.24.04.5' },
    expect: { verdict: 'verify', version: '8.3.6', os: 'Ubuntu 24.04' },
  },
  {
    name: 'ubuntu-1804-servertokens-full',
    about: 'mod_php version only in the Server header (ServerTokens Full)',
    headers: { server: 'Apache/2.4.29 (Ubuntu) PHP/7.2.24-0ubuntu0.18.04.17 OpenSSL/1.1.1' },
    expect: { verdict: 'verify', version: '7.2.24', os: 'Ubuntu 18.04', sapi: 'mod_php (Apache module)' },
  },
  {
    name: 'debian-11-nginx-fpm',
    about: 'Debian 11 archive PHP-FPM behind nginx',
    headers: { server: 'nginx/1.18.0', 'x-powered-by': 'PHP/7.4.33-1+deb11u5' },
    expect: { verdict: 'verify', version: '7.4.33', os: 'Debian 11', sapi: 'likely PHP-FPM (behind nginx)' },
  },
  {
    name: 'docker-php-8.3.30-apache',
    about: 'Official php:8.3.30-apache image (source build on Debian – no backports)',
    headers: { server: 'Apache/2.4.62 (Debian)', 'x-powered-by': 'PHP/8.3.30' },
    expect: { verdict: 'vulnerable', version: '8.3.30', fixedIn: '8.3.36' },
  },
  {
    name: 'docker-php-8.4.27-fpm',
    about: 'Official php:8.4.27-fpm behind nginx (fixed release)',
    headers: { server: 'nginx/1.27.4', 'x-powered-by': 'PHP/8.4.27' },
    expect: { verdict: 'patched', version: '8.4.27' },
  },
  {
    name: 'boundary-8.5.11',
    about: 'Last affected 8.5 release',
    headers: { server: 'nginx', 'x-powered-by': 'PHP/8.5.11' },
    expect: { verdict: 'vulnerable', version: '8.5.11', fixedIn: '8.5.12' },
  },
  {
    name: 'boundary-8.2.34',
    about: 'Last affected 8.2 release',
    headers: { 'x-powered-by': 'PHP/8.2.34' },
    expect: { verdict: 'vulnerable', version: '8.2.34', fixedIn: '8.2.35' },
  },
  {
    name: 'rhel-9-apache',
    about: 'RHEL 9 AppStream PHP – plain upstream version, vendor backports',
    headers: { server: 'Apache/2.4.57 (Red Hat Enterprise Linux) OpenSSL/3.0.7', 'x-powered-by': 'PHP/8.0.30' },
    expect: { verdict: 'verify', version: '8.0.30' },
  },
  {
    name: 'sury-ppa-nginx',
    about: 'Ondřej Surý PPA build (upstream release, version is authoritative)',
    headers: { server: 'nginx/1.18.0 (Ubuntu)', 'x-powered-by': 'PHP/8.2.20-1+ubuntu22.04.1+deb.sury.org+1' },
    expect: { verdict: 'vulnerable', version: '8.2.20', fixedIn: '8.2.35', os: 'Ubuntu 22.04' },
  },
  {
    name: 'plesk-shared-hosting',
    about: 'Plesk: two X-Powered-By headers merged',
    headers: { server: 'nginx', 'x-powered-by': ['PHP/8.1.29', 'PleskLin'] },
    expect: { verdict: 'vulnerable', version: '8.1.29' },
  },
  {
    name: 'windows-iis',
    about: 'PHP on IIS with ASP.NET header',
    headers: { server: 'Microsoft-IIS/10.0', 'x-powered-by': ['PHP/7.4.33', 'ASP.NET'] },
    expect: { verdict: 'vulnerable', version: '7.4.33', os: 'Windows Server 2016 / 2019 / 2022' },
  },
  {
    name: 'litespeed-patched',
    about: 'LiteSpeed shared host on a fixed release',
    headers: { server: 'LiteSpeed', 'x-powered-by': 'PHP/8.2.35' },
    expect: { verdict: 'patched', version: '8.2.35', sapi: 'likely LSAPI (LiteSpeed)' },
  },
  {
    name: 'wordpress-behind-cloudflare',
    about: 'Hidden version; WordPress REST link; Cloudflare edge',
    headers: { server: 'cloudflare', 'cf-ray': '8d1f0000aaaa-SIN', link: '<https://example.org/wp-json/>; rel="https://api.w.org/"' },
    body: '<html><link rel="stylesheet" href="/wp-content/themes/x/style.css"></html>',
    expect: { verdict: 'unknown', cdn: 'Cloudflare', context: ['wordpress', 'cloudflare'] },
  },
  {
    name: 'laravel-hardened',
    about: 'expose_php=Off; only the framework session cookie gives PHP away',
    headers: { server: 'nginx', 'set-cookie': 'laravel_session=eyJpdiI6; path=/; httponly' },
    expect: { verdict: 'unknown' },
  },
  {
    name: 'static-site',
    about: 'No PHP at all',
    headers: { server: 'nginx/1.25.3' },
    expect: { verdict: 'no-php' },
  },
  {
    name: 'redirect-chain',
    about: 'apex -> www redirect; PHP banner only on the final page',
    redirectTo: 'www',
    headers: { server: 'Apache', 'x-powered-by': 'PHP/8.3.20' },
    expect: { verdict: 'vulnerable', version: '8.3.20', redirects: 1 },
  },
  {
    name: 'redirect-to-private-ip',
    about: 'Redirect into a private address must not be followed (SSRF), earlier hop still reported',
    redirectTo: 'http://169.254.169.254/latest/meta-data/',
    headers: { 'x-powered-by': 'PHP/8.4.10' },
    expect: { verdict: 'vulnerable', version: '8.4.10', finding: 'redirect-blocked' },
  },
  {
    name: 'edge-fetch-non-cloudflare-origin',
    about: "Production fallback path: Cloudflare's fetch stamps Server/CF-RAY; target is NOT on Cloudflare",
    headers: { server: 'cloudflare', 'cf-ray': 'a4e56dc6dc5a55f9-KUL', 'cf-cache-status': 'DYNAMIC', 'x-phpchecker-transport': 'edge-fetch', 'x-powered-by': 'PHP/8.4.20' },
    dns: ['93.184.216.34'],
    expect: { verdict: 'vulnerable', version: '8.4.20', cdn: null, webserver: null },
  },
  {
    name: 'edge-fetch-cloudflare-origin',
    about: 'Production fallback path: target IS on Cloudflare (confirmed via DNS)',
    headers: { server: 'cloudflare', 'cf-ray': 'a4e56dc6dc5a55f9-KUL', 'x-phpchecker-transport': 'edge-fetch', 'set-cookie': 'PHPSESSID=x; path=/' },
    dns: ['104.16.132.229'],
    expect: { verdict: 'unknown', cdn: 'Cloudflare', context: ['cloudflare'], webserver: null },
  },
  {
    name: 'bot-challenge',
    about: 'Cloudflare challenge page: incomplete result must be flagged',
    status: 403,
    headers: { server: 'cloudflare', 'cf-ray': 'x', 'cf-mitigated': 'challenge' },
    expect: { verdict: 'no-php', finding: 'http-error' },
  },
];
