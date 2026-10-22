# PHPChecker

**Open-source (MIT) scanner that checks websites for the "php2shell" PHP vulnerabilities:**

* **CVE-2026-109618** – an out-of-memory handling vulnerability that could allow an unauthenticated remote attacker to execute arbitrary code on affected systems.
* **CVE-2026-109619** – a use-after-free vulnerability that could allow an unauthenticated remote attacker to execute arbitrary code on affected systems.

Affected: PHP 5.4.0 – 8.5.11. Fixed in **8.2.35, 8.3.36, 8.4.27 and 8.5.12**. PHP 8.1 and older are end-of-life and get no upstream fix.

Live: https://phpchecker.sanjay6326.workers.dev · One Cloudflare Worker, no database, no build step, no runtime dependencies.

## Privacy: what is tracked

**Nothing is tracked except scan requests**, which are logged for safety and audit-trail purposes.
Each scan request writes one log line: time, requester IP address and country, browser user agent,
the target's **hostname** (never its path or query string) and the result. There are no cookies, no analytics
and no third-party scripts. Version lookups via `/api/version` are not logged. Logs live in Cloudflare
Workers Logs for the account that deploys the Worker.

## How it works

You enter a website URL. PHPChecker makes one ordinary `GET` request (following up to 3 redirects),
reads the response headers and up to 64 KB of HTML, and:

0. Connects over a **direct TLS/TCP socket** from the Worker, so the headers are exactly what the site sent.
   (Cloudflare rewrites `Server`/`CF-RAY` on Worker `fetch()` responses. Workers can't open sockets to Cloudflare's
   own IPs, so Cloudflare-hosted sites go through `fetch()`: their origin web server is hidden, and DNS confirms
   whether they are on Cloudflare. `X-Powered-By` and cookies are unaffected either way.)

1. Finds the PHP version the site discloses (`X-Powered-By`, or `Server` with ServerTokens Full).
2. Compares it with the affected range and fixed releases above.
3. Accounts for distro builds: Ubuntu/Debian/RHEL often backport fixes without changing the version,
   so those results say **verify** (check the package changelog), not "vulnerable".
4. Fingerprints the web server, likely SAPI (mod_php / PHP-FPM), OS hint, CDN and CMS. A **Details** button shows
   everything found and every check performed or skipped.
5. Ranks 47 help resources for the result: patching commands per platform, backport verification, php.ini
   hardening, ModSecurity/nginx/Apache/Cloudflare workarounds, EOL options, detection rules, hunting,
   incident response and a leadership brief.

Verdicts: `vulnerable` · `verify` · `patched` · `unknown` (PHP found, version hidden – **not** proof of safety) · `no-php`.

### What it does not do

It never exploits or triggers the bugs: no uploads, no multipart bodies, no `PHP_SESSION_UPLOAD_PROGRESS`,
no payloads, no crawling. It cannot see `php.ini` settings or a version the server hides. A server-side
check (`php -v`, package changelog) is always the final word.

## Validation

`npm run validate` runs the **real scanner over real HTTP** (only DNS is replaced: public-looking hostnames
route to local servers) and checks results against an expectation table written independently from the advisory:

* 19 real-world header profiles – Ubuntu 18.04/22.04/24.04, Debian 11, RHEL 9, official Docker images,
  Surý PPA, Plesk, IIS, LiteSpeed, WordPress behind Cloudflare, hardened Laravel, static sites, redirect chains,
  bot challenges, and the exact boundary releases (8.2.34 vs 8.2.35, 8.5.11 vs 8.5.12).
* Every real PHP interpreter it finds on the machine, served with `php -S` (with `expose_php` on and off),
  using `PHP_VERSION` as ground truth.
* The passive-scan promises: every request the scanner sends is recorded and must be a body-less `GET`;
  HTML reads stop at 64 KB; unresponsive sites time out; redirects into private addresses are never followed.

CI runs the same validation against real PHP 7.4, 8.1, 8.3 and 8.5 (`.github/workflows/ci.yml`).
The production transport (direct sockets + Cloudflare fallback) was additionally checked on Cloudflare's edge
against live sites, plus httpbin.org for controlled `X-Powered-By` banners.

## Run locally

```bash
npm install
npm run dev        # http://localhost:8787
npm test           # unit tests
npm run validate   # end-to-end validation (uses any PHP installed locally)
```

## Deploy your own

```bash
npx wrangler login
npm run deploy
```

Rate limiting uses the `[[ratelimits]]` binding in `wrangler.toml` (10 scans per minute per IP), with a per-isolate
fallback. If you deploy your own instance, set a log retention period and publish a privacy notice that fits your jurisdiction.

## API

| Endpoint | Description |
| --- | --- |
| `GET /api/scan?url=example.com&authorized=1` | Scan a website. `authorized=1` confirms you own it or are authorised to test it. Logged. Not callable cross-site from browsers. |
| `GET /api/version?v=8.3.30` | Check a version string. No network request, not logged. |
| `GET /api/resources` | The help library as JSON. |
| `GET /healthz` | Liveness. |

## Safety

* Only public domain names: IP literals, `localhost`, internal suffixes, wildcard-DNS services (nip.io, sslip.io…)
  and unusual ports are refused, and every redirect hop is re-checked. Cloudflare's egress also cannot reach private networks.
* `/api/scan` sends no CORS headers and refuses browser requests marked `Sec-Fetch-Site: cross-site`, so other
  sites can't use visitors' browsers to launch scans.
* Submitting a scan in the UI confirms you own the site or are authorised to test it.
* The UI builds all dynamic content with `textContent` and ships a nonce-based CSP.

## Keeping data current

Advisory facts live in [`src/advisory.js`](src/advisory.js); the help library is in [`src/resources.js`](src/resources.js).
They come from the [ikow/php2shell-poc](https://github.com/ikow/php2shell-poc) README and the advisories and
vendor writeups it links. The fixed releases match the PHP versions Homebrew ships (8.2.35, 8.3.36, 8.4.27, 8.5.12).
Distro-tracker links are built from the CVE IDs and may 404 until each vendor publishes its page. PRs welcome.

## Layout

```
src/index.js        router, CSP, rate limit, cross-site guard, scan audit log
src/validate.js     target normalisation + SSRF guard
src/scanner.js      passive scan, findings, verdict, details
src/transport.js    direct TLS/TCP HTTP client for the edge, Cloudflare fallback, DNS check
src/version.js      PHP token extraction, backport detection, advisory comparison
src/fingerprint.js  web server / OS hints from banners
src/advisory.js     CVE facts (single source of truth)
src/resources.js    help library
src/ui.js           the search page
src/project.js      project name, repo, URL
test/               unit tests (node --test)
validation/         end-to-end validation harness
docs/PLAN.md        design notes
```

## License

MIT – see [LICENSE](LICENSE).
