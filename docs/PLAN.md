# PHPChecker – design notes

Open-source, **passive** website scanner for the "php2shell" CVEs (CVE-2026-109618, CVE-2026-109619),
packaged as a single Cloudflare Worker with a Google-style home page. Upstream research:
https://github.com/ikow/php2shell-poc

## Goals

1. One line: enter a website URL, get a verdict below it, keeping the home-page layout.
2. Answer "is this site exposed?" honestly, including "can't tell" (most sites hide their version).
3. Turn the answer into action: ranked, copy-pasteable fixes, workarounds, detection and response help.
4. Pure Worker: no KV/D1/containers, no build step, no runtime dependencies.
5. Provably works as advertised: an end-to-end validation harness, also run in CI against real PHP.

## Safety stance

* **No exploitation.** One `GET` per hop (max 3 redirects), headers plus at most 64 KB of HTML. Never
  multipart bodies, upload-progress markers or payloads. The validation harness records every request to prove it.
* Verdicts never over-claim: `vulnerable | verify | patched | unknown | no-php`. Distro builds whose
  vendors backport (Ubuntu/Debian package suffixes, RHEL-family plain versions) become `verify`. Surý/Remi and
  official Docker builds carry upstream versions, so their numbers are trusted.
* Abuse controls: implicit consent on submit (`authorized=1` required by the API), SSRF guard (no IP literals,
  internal names, wildcard-DNS services or odd ports; every redirect re-checked; private redirects are reported, not
  followed), cross-site browser requests refused, rate limit (binding + per-isolate fallback), identifiable User-Agent.

## Tracking

Nothing is tracked except scan requests, logged for safety and audit-trail purposes: one JSON line per
scan request via `console.log`, kept by Workers Logs (`[observability]`). Fields: time, IP, country, user agent, target
**hostname only**, outcome. No cookies, analytics or third-party scripts. The page states this in the
footer and on every result.

## Architecture

```
src/index.js      router, CSP nonce, rate limiting, cross-site guard, audit log
src/validate.js   target normalisation + SSRF guard
src/scanner.js    passive fetch (one 10 s budget), fingerprinting, findings, verdict, details
src/transport.js  HTTP/1.1 over cloudflare:sockets (genuine headers); fetch fallback for Cloudflare-hosted
                  targets, whose edge-stamped Server/CF-RAY/CF-Cache-Status are ignored; DoH check for Cloudflare IPs
src/version.js    PHP token extraction, backport detection, advisory assessment
src/fingerprint.js web server / OS hints
src/advisory.js   CVE facts: affected range, fixed releases  <- update here
src/resources.js  help library
src/ui.js         the page (vanilla JS, DOM built with textContent only)
src/project.js    name / repo / URL
test/             unit tests (node --test)
validation/       real-HTTP validation harness + real-world header profiles + php -S app
```

## Verdict logic

| Signal | Result |
| --- | --- |
| Version 8.2–8.5 and patch ≥ fixed (35/36/27/12) | `patched` |
| Version 8.2–8.5 below fixed | `vulnerable` (fix exists) |
| Version 5.4–8.1 | `vulnerable` (EOL – no upstream fix) |
| Either of the above on a backporting distro build | `verify` |
| PHP signals but no version | `unknown` |
| No PHP signals | `no-php` (not proof) |

## Roadmap

* Optional, opt-in probes for exposed `phpinfo()` pages (would reveal the real `session.upload_progress` value).
* `ALLOWLIST_TARGETS` / `DENYLIST_TARGETS` env vars for operators.
* Re-verify CVE data against php.net as vendor pages are published.
