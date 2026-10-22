import { ADVISORY } from './advisory.js';

/**
 * Help library shown under every result. Two kinds of entries:
 *   link  – {title, url, snippet}
 *   guide – {title, snippet, sections:[{h?, text?, code?}]} expandable playbooks
 * `category`: fix | detect | advisory | read.   `when`: context tags that make an entry
 * relevant to a specific scan result (see scanner.js `context`). Empty = always.
 */

const [C1, C2] = ADVISORY.cves.map((c) => c.id);
const R = ADVISORY.repo;

const links = [
  // ---- Advisories & patches ----
  { id: 'php-advisory', category: 'advisory', title: 'PHP security advisory (php.net)', url: 'https://www.php.net/archive/2026.php', snippet: 'Official announcement of the fixed releases: 8.2.35, 8.3.36, 8.4.27 and 8.5.12.', when: [] },
  { id: 'ghsa-1', category: 'advisory', title: `${ADVISORY.cves[0].ghsa} – ${C1}`, url: `https://github.com/php/php-src/security/advisories/${ADVISORY.cves[0].ghsa}`, snippet: `CVSS ${ADVISORY.cves[0].cvss}. ${ADVISORY.cves[0].summary}`, when: [] },
  { id: 'ghsa-2', category: 'advisory', title: `${ADVISORY.cves[1].ghsa} – ${C2}`, url: `https://github.com/php/php-src/security/advisories/${ADVISORY.cves[1].ghsa}`, snippet: `CVSS ${ADVISORY.cves[1].cvss}. ${ADVISORY.cves[1].summary}`, when: [] },
  { id: 'patch', category: 'advisory', title: 'Upstream patch – php-src commit 3584a98', url: 'https://github.com/php/php-src/commit/3584a98bda', snippet: 'The engine-level fix. Useful for vendors backporting to branches that no longer get upstream releases.', when: ['eol', 'distro'] },
  { id: 'php-downloads', category: 'advisory', title: 'Download fixed PHP releases', url: 'https://www.php.net/downloads.php', snippet: 'Source tarballs for 8.2.35+, 8.3.36+, 8.4.27+ and 8.5.12+. Prefer your distro packages or official Docker images where possible.', when: ['vulnerable'] },
  { id: 'php-supported', category: 'advisory', title: 'PHP supported versions', url: 'https://www.php.net/supported-versions.php', snippet: 'Branches outside this table (including 8.1 and older) receive no upstream fix – plan an upgrade or buy extended support.', when: ['eol'] },
  { id: 'cve-1', category: 'advisory', title: `${C1} – CVE.org record`, url: `https://www.cve.org/CVERecord?id=${C1}`, snippet: 'Canonical CVE record.', when: [] },
  { id: 'cve-2', category: 'advisory', title: `${C2} – CVE.org record`, url: `https://www.cve.org/CVERecord?id=${C2}`, snippet: 'Canonical CVE record.', when: [] },
  { id: 'nvd-1', category: 'advisory', title: `${C1} – NVD`, url: `https://nvd.nist.gov/vuln/detail/${C1}`, snippet: 'NIST National Vulnerability Database entry with CPE/version data once analysed.', when: [] },
  { id: 'nvd-2', category: 'advisory', title: `${C2} – NVD`, url: `https://nvd.nist.gov/vuln/detail/${C2}`, snippet: 'NIST National Vulnerability Database entry with CPE/version data once analysed.', when: [] },
  { id: 'debian-1', category: 'advisory', title: `Debian Security Tracker – ${C1}`, url: `https://security-tracker.debian.org/tracker/${C1}`, snippet: 'Per-release package status for Debian (and derivatives). Look for your suite and the fixed package version.', when: ['distro'] },
  { id: 'debian-2', category: 'advisory', title: `Debian Security Tracker – ${C2}`, url: `https://security-tracker.debian.org/tracker/${C2}`, snippet: 'Per-release package status for Debian (and derivatives).', when: ['distro'] },
  { id: 'ubuntu-1', category: 'advisory', title: `Ubuntu Security – ${C1}`, url: `https://ubuntu.com/security/${C1}`, snippet: 'Per-release status for Ubuntu, including ESM (Ubuntu Pro) coverage for older releases.', when: ['distro'] },
  { id: 'ubuntu-2', category: 'advisory', title: `Ubuntu Security – ${C2}`, url: `https://ubuntu.com/security/${C2}`, snippet: 'Per-release status for Ubuntu, including ESM (Ubuntu Pro) coverage for older releases.', when: ['distro'] },
  { id: 'rh-1', category: 'advisory', title: `Red Hat CVE page – ${C1}`, url: `https://access.redhat.com/security/cve/${C1}`, snippet: 'RHEL / CentOS Stream / Alma / Rocky errata and affected-package status.', when: ['distro'] },
  { id: 'rh-2', category: 'advisory', title: `Red Hat CVE page – ${C2}`, url: `https://access.redhat.com/security/cve/${C2}`, snippet: 'RHEL / CentOS Stream / Alma / Rocky errata and affected-package status.', when: ['distro'] },
  { id: 'suse-1', category: 'advisory', title: `SUSE CVE page – ${C1}`, url: `https://www.suse.com/security/cve/${C1}.html`, snippet: 'SLES / openSUSE package status.', when: ['distro'] },
  { id: 'suse-2', category: 'advisory', title: `SUSE CVE page – ${C2}`, url: `https://www.suse.com/security/cve/${C2}.html`, snippet: 'SLES / openSUSE package status.', when: ['distro'] },
  { id: 'alpine-1', category: 'advisory', title: `Alpine security tracker – ${C1}`, url: `https://security.alpinelinux.org/vuln/${C1}`, snippet: 'Alpine package status – the base of many official php:*-alpine Docker images.', when: ['distro'] },
  { id: 'alpine-2', category: 'advisory', title: `Alpine security tracker – ${C2}`, url: `https://security.alpinelinux.org/vuln/${C2}`, snippet: 'Alpine package status.', when: ['distro'] },
  { id: 'amzn-1', category: 'advisory', title: `Amazon Linux Security Center – ${C1}`, url: `https://explore.alas.aws.amazon.com/${C1}.html`, snippet: 'Amazon Linux 2 / 2023 advisories and fixed package versions.', when: ['distro'] },
  { id: 'amzn-2', category: 'advisory', title: `Amazon Linux Security Center – ${C2}`, url: `https://explore.alas.aws.amazon.com/${C2}.html`, snippet: 'Amazon Linux 2 / 2023 advisories and fixed package versions.', when: ['distro'] },
  { id: 'docker-php', category: 'advisory', title: 'Official PHP Docker image tags', url: 'https://hub.docker.com/_/php', snippet: 'Rebuild with --pull and pin a tag at or above the fixed version (e.g. 8.4.27-fpm). Images are not patched in place.', when: [] },
  { id: 'sury', category: 'advisory', title: 'Debian/Ubuntu PHP packages (deb.sury.org)', url: 'https://deb.sury.org/', snippet: 'Third-party PHP repository many Debian/Ubuntu servers use; check it carries the fixed build before relying on it.', when: ['distro'] },
  { id: 'remi', category: 'advisory', title: "Remi's RPM repository", url: 'https://rpms.remirepo.net/', snippet: "Sansec noted the fix was not yet available here on release day – verify the package version before assuming you're covered.", when: ['distro'] },

  // ---- Writeups ----
  { id: 'repo', category: 'read', title: 'ikow/php2shell-poc – exploit & detection toolkit', url: R, snippet: 'Upstream research this scanner is based on: attack chains A–E, lab, and detection rules. Exploit scripts there are for authorised testing only.', when: [] },
  { id: 'analysis', category: 'read', title: 'php2shell technical analysis (ANALYSIS.md)', url: `${R}/blob/main/docs/ANALYSIS.md`, snippet: 'Root-cause write-up of the OOM/longjmp and stale-state flaws and how each attack chain depends on SAPI and app behaviour.', when: [] },
  { id: 'substack', category: 'read', title: 'php2shell: dissecting PHP\'s critical flaws (Qi Deng)', url: 'https://qideng.substack.com/p/php2shell-dissecting-phps-critical', snippet: "Author's long-form writeup.", when: [] },
  { id: 'sansec', category: 'read', title: 'Sansec – php2shell', url: 'https://sansec.io/research/php2shell', snippet: 'Affected platforms (Magento, WordPress, Drupal, Joomla, MediaWiki, Nextcloud, Laravel…), temporary mitigations and what to hunt for.', when: ['magento', 'wordpress', 'drupal', 'joomla', 'mediawiki'] },
  { id: 'wiz', category: 'read', title: 'Wiz – php2shell downstream impact', url: 'https://www.wiz.io/blog/php2shell-php-rce', snippet: 'Container images and CMS exposure, rebuild/redeploy advice, secrets-rotation guidance and detection signals.', when: [] },
  { id: 'cloudflare-blog', category: 'read', title: 'Cloudflare – WAF protection for the PHP vulnerabilities', url: 'https://blog.cloudflare.com/php-vulnerabilities-waf-protection/', snippet: 'Managed rule IDs per plan and how to confirm they are in block mode.', when: ['cloudflare'] },

  // ---- Detection ----
  { id: 'detect-dir', category: 'detect', title: 'Detection rules: Suricata/Snort, Sigma, ModSecurity, OpenResty Lua', url: `${R}/tree/main/detection`, snippet: '13 network rules, 5 Sigma rules (web logs, process creation, file events), 7 ModSecurity rules and a Lua module. SID 2026100 (upload-progress marker in multipart POST) is the highest-value rule.', when: [] },
  { id: 'corelight', category: 'detect', title: 'Corelight php2shell-detect (Zeek + Suricata)', url: 'https://github.com/corelight/php2shell-detect', snippet: 'Zeek package (zkg install) and Suricata rules SID 3000650–3000652, including a PHP version inventory from Server/X-Powered-By headers. Needs plaintext HTTP visibility.', when: [] },
];

const guides = [
  {
    id: 'g-inventory',
    category: 'fix',
    title: 'Find every PHP runtime you operate (and check the right one)',
    snippet: 'The CLI version is often not the one serving web traffic. Inventory FPM, mod_php, containers and bundled images.',
    when: [],
    sections: [
      { text: 'Check the SAPI that actually serves requests – `php -v` reports the CLI only. Include containers, CI images, staging, and vendor appliances that bundle PHP (CMS images, control panels).' },
      {
        h: 'Host',
        code: `php -v                              # CLI only – may differ from web
php-fpm8.3 -v || php-fpm -v         # binary name varies by distro
apache2ctl -M 2>/dev/null | grep -i php   # mod_php?
php-fpm8.3 -i | grep -E 'session.upload_progress.enabled|session.use_only_cookies|memory_limit'   # effective FPM settings
ls /etc/php/*/ 2>/dev/null          # Debian/Ubuntu: all installed branches`,
      },
      {
        h: 'Containers',
        code: `docker ps --format '{{.Image}}' | sort -u
docker run --rm --entrypoint php IMAGE -v      # repeat per image
kubectl get pods -A -o jsonpath='{range .items[*]}{.spec.containers[*].image}{"\\n"}{end}' | sort -u`,
      },
      { text: 'Prioritise: internet-facing first, then anything handling payments or secrets, then internal apps.' },
    ],
  },
  {
    id: 'g-patch',
    category: 'fix',
    title: 'Patch PHP: commands for Debian/Ubuntu, RHEL, Alpine, Docker, cPanel',
    snippet: 'Patching PHP itself is the only complete fix. Updating the app, plugins or CMS does not help.',
    when: ['vulnerable', 'verify', 'unknown', 'distro'],
    sections: [
      { text: 'Target: 8.2.35, 8.3.36, 8.4.27 or 8.5.12 (or newer) – or your distro\'s package that lists CVE-2026-109618 / CVE-2026-109619 in its changelog.' },
      { h: 'Debian / Ubuntu', code: `sudo apt-get update
sudo apt-get install --only-upgrade 'php*'
sudo systemctl restart php8.3-fpm apache2    # adjust unit names` },
      { h: 'RHEL / Alma / Rocky / Fedora / Amazon Linux', code: `sudo dnf upgrade --refresh 'php*'
sudo systemctl restart php-fpm httpd` },
      { h: 'Alpine', code: `apk update && apk upgrade    # apk has no package globs; for images, rebuild instead` },
      { h: 'Docker – images are immutable, rebuild them', code: `# Dockerfile: pin a fixed tag
FROM php:8.4.27-fpm
# then
docker build --pull --no-cache -t myapp:patched .
# redeploy and retire every old tag/replica` },
      { h: 'cPanel / WHM (EasyApache 4)', code: `dnf upgrade 'ea-php*'    # or use WHM > EasyApache 4 / Software > update` },
      { text: 'Shared or managed hosting: you cannot patch it yourself – open a ticket today asking for the patched PHP build and the date it will be live.' },
    ],
  },
  {
    id: 'g-backport',
    category: 'fix',
    title: 'Verify a distro backport (version string alone proves nothing)',
    snippet: 'Debian, Ubuntu and RHEL often fix bugs without bumping the upstream version. Confirm via the changelog.',
    when: ['distro', 'verify'],
    sections: [
      { code: `# Debian / Ubuntu
apt changelog php8.3-fpm | grep -Ei 'CVE-2026-10961[89]'
dpkg -l | grep -i php

# RHEL family
rpm -q --changelog php-fpm | grep -Ei 'CVE-2026-10961[89]'

# Alpine (no changelog grep: compare the package version with the Alpine tracker)
apk info -v 'php*'` },
      { text: 'If the changelog mentions both CVEs, you are on a fixed build even though the banner looks old. If not, ask the vendor for an ETA or move to a build you can verify.' },
    ],
  },
  {
    id: 'g-eol',
    category: 'fix',
    title: 'Running PHP 8.1 or older? Options when upstream has no fix',
    snippet: 'Branches 5.4–8.1 are affected but end-of-life. Upgrade, buy a vendor backport, or isolate while you migrate.',
    when: ['eol'],
    sections: [
      { text: 'Choose in this order:' },
      { text: '1) Upgrade to a supported branch (8.2+; prefer the newest your app supports). Use Rector and `phpcompatibility/php-compatibility` in CI to find breakage; stage first.' },
      { text: '2) Vendor extended support: ask your OS vendor or support provider (e.g. Ubuntu Pro/ESM, Debian LTS, RHEL subscription, third-party extended-lifecycle PHP vendors) whether they ship the backport of upstream commit 3584a98 – then verify via the changelog (see "Verify a distro backport").' },
      { text: '3) Self-backport only with a team that can maintain it: the upstream change touches ~300 files across the Zend engine.' },
      { text: '4) Until migrated: apply the php.ini hardening and edge-blocking guides, put the app behind a WAF, restrict to GET/HEAD where possible, and reduce blast radius.' },
    ],
  },
  {
    id: 'g-ini',
    category: 'fix',
    title: 'Can\'t patch today? php.ini hardening (reduces attack surface only)',
    snippet: 'Disable session upload progress and tighten session handling. Not a complete fix – the Zend core flaw is not controllable by INI.',
    when: ['vulnerable', 'verify', 'unknown', 'session', 'eol'],
    sections: [
      { code: `; /etc/php/8.x/fpm/conf.d/99-php2shell-mitigation.ini   (also apply to apache2/ and cli/ if used)
session.upload_progress.enabled = Off
session.use_only_cookies = On
session.use_strict_mode = On     ; general session hardening` },
      { text: 'Reload: `systemctl reload php8.x-fpm` (or restart Apache for mod_php). Apps that show upload progress bars via the session feature will lose them.' },
      { text: 'If you run several FPM pools or directories with different `session.serialize_handler` values, align them (one of the documented chains depends on a handler mismatch).' },
      { text: 'Sansec also lists setting `memory_limit` to -1 as a stop-gap, but that lets one request consume all memory. Only consider it with strict process/cgroup limits and revert after patching.' },
      { text: 'Verify with `php-fpm8.x -i | grep upload_progress` – check the FPM/Apache SAPI, not the CLI.' },
    ],
  },
  {
    id: 'g-waf',
    category: 'fix',
    title: 'Edge blocking: ModSecurity, nginx and Apache rules',
    snippet: 'Block the PHP_SESSION_UPLOAD_PROGRESS marker, or (emergency) multipart bodies on routes that don\'t need uploads.',
    when: ['vulnerable', 'verify', 'unknown', 'eol', 'mod_php', 'fpm'],
    sections: [
      { h: 'ModSecurity (v2/v3) – run in DetectionOnly first', code: `SecRequestBodyAccess On
SecRequestBodyLimitAction Reject      # reject, don't pass oversized bodies (padding bypass)
SecRule ARGS_NAMES|FILES_NAMES|MULTIPART_PART_HEADERS|REQUEST_BODY "@contains PHP_SESSION_UPLOAD_PROGRESS" \\
  "id:26101,phase:2,t:none,deny,status:403,log,msg:'PHP session upload-progress marker (php2shell)'"` },
      { text: 'WAFs that inspect only the first 64 KB can be bypassed by padding the request – treat this as a layer, and turn `session.upload_progress.enabled` off as well. The ready-made rules in the repo\'s detection/modsecurity.conf cover more cases.' },
      { h: 'nginx – emergency: refuse multipart on non-upload routes', code: `location ~ \\.php$ {
    if ($content_type ~* "^multipart/form-data") { return 403; }
    # ... your existing fastcgi_pass ...
}` },
      { h: 'Apache – emergency: refuse multipart on non-upload paths', code: `<If "%{HTTP:Content-Type} =~ m#^multipart/form-data#i">
    Require all denied
</If>` },
      { text: 'This breaks file uploads (comments, avatars, some checkouts). Scope it to paths that never upload, and test an order/login after deploying.' },
      { text: 'Maintenance modes in WordPress/Magento do not help: PHP parses the request before application code runs.' },
    ],
  },
  {
    id: 'g-cloudflare',
    category: 'fix',
    title: 'Cloudflare customers: confirm managed rules are blocking',
    snippet: 'Free plans get protection by default; paid plans must have the Managed Ruleset in block mode.',
    when: ['cloudflare'],
    sections: [
      { text: 'Rules are "Generic Rules - Anomalous Execution 1–7" plus "Managed Response Firewall Default". Check Security → Events filtered by these IDs.' },
      { code: `Free   – Cloudflare Managed Free Ruleset 77454fe2d30c4220b5701f6fdfb893ba
Pro/Biz/Ent – Cloudflare Managed Ruleset  efb7b8c949ac4650a09736fc376e9aee
All    – Managed Response Firewall Default  afffe22785674c80a31875c848d2242a` },
      { text: 'Cloudflare says this is an extra layer; you still have to patch PHP, and your origin must not be reachable by bypassing the proxy (lock origin access to Cloudflare IPs / use Authenticated Origin Pulls).' },
    ],
  },
  {
    id: 'g-blast',
    category: 'fix',
    title: 'Reduce blast radius while you patch',
    snippet: 'Defence in depth: isolate pools, read-only filesystems, egress control, shorter-lived workers and secrets.',
    when: [],
    sections: [
      { text: 'These do not fix the bug; they limit what an attacker gets if a worker is compromised or its memory is read.' },
      { text: '• One FPM pool/user per site; no shared secrets between pools. Run web roots read-only (`chattr`/read-only mounts); writable dirs only for uploads/cache, mounted `noexec`.' },
      { text: '• Containers: `readOnlyRootFilesystem`, drop all capabilities, non-root user, no cloud-metadata access from web pods (block 169.254.169.254 / enforce IMDSv2 hop limit 1).' },
      { text: '• Egress filtering: web servers rarely need arbitrary outbound access – allow only the DBs/APIs you use. Alert on new outbound destinations.' },
      { text: '• Recycle workers more aggressively while exposed (defence in depth, not a fix): lower `pm.max_requests` in the FPM pool, then restart after patching.' },
      { text: '• Short-lived credentials: process memory can hold DB passwords, API keys and TLS keys. Prefer secrets managers and rotate on any suspicion (see the incident response checklist).' },
    ],
  },
  {
    id: 'g-hosting',
    category: 'fix',
    title: 'Shared hosting, agencies and CMS owners (WordPress, Magento, Drupal, Joomla…)',
    snippet: 'The bug is in PHP, not your plugins. Here is what to ask your host and what you can do yourself.',
    when: ['wordpress', 'magento', 'drupal', 'joomla', 'mediawiki', 'phpmyadmin'],
    sections: [
      { text: 'Ask your host (copy/paste): "Please confirm which PHP version/build serves <domain>, whether it includes the fixes for CVE-2026-109618 and CVE-2026-109619, and when workers were restarted. If not yet, what is the ETA?"' },
      { text: 'Self-service: switch the site to the newest PHP your host offers (cPanel "MultiPHP Manager", Plesk, hosting dashboards) that is on a fixed release; test after switching.' },
      { text: 'Updating WordPress/Magento/plugins does not remove the PHP flaw, but do it anyway; keep a WAF (Cloudflare or your host\'s) on in front.' },
      { text: 'Magento: Sansec reports Magento/Shopware/WooCommerce stores are exposed even with clean app code; if you must block multipart temporarily, test the full checkout.' },
    ],
  },
  {
    id: 'g-after',
    category: 'fix',
    title: 'After patching: restart, rebuild, validate',
    snippet: 'Stale workers keep running the old code and state until restarted.',
    when: [],
    sections: [
      { code: `sudo systemctl restart php8.3-fpm        # restart, not just reload, to flush worker state
sudo systemctl restart apache2           # mod_php: Apache embeds PHP
docker compose up -d --force-recreate    # containers: new image, new containers` },
      { text: 'Validate: `php-fpm8.x -v` / package changelog (see "Verify a distro backport"), re-run this scanner, and confirm every replica and autoscaling image is rebuilt. Re-check dev/staging/CI images and any hosts missed in the inventory.' },
      { text: 'The PHP team says the fix covers variants of the same flaws, not just the reported bugs – keep applying later PHP point releases.' },
    ],
  },
  {
    id: 'g-ir',
    category: 'fix',
    title: 'Suspect compromise? Incident response checklist',
    snippet: 'Assume memory-resident secrets may be exposed; contain, rotate, rebuild from clean images.',
    when: ['vulnerable', 'verify', 'unknown'],
    sections: [
      { text: '1) Contain: isolate the host/pod from the network, snapshot disk and memory for forensics before wiping.' },
      { text: '2) Rotate everything the PHP process could reach: DB passwords, API keys, app secrets/salts (e.g. WordPress salts, Laravel APP_KEY), session secrets, TLS private keys, cloud credentials. Invalidate all sessions.' },
      { text: '3) Rebuild from a clean, patched image; do not "clean in place". Redeploy code from version control, not from the compromised disk.' },
      { text: '4) Review lateral movement: DB access logs, cloud audit logs, new users/SSH keys/cron entries, outbound connections.' },
      { text: '5) Notify according to your legal/regulatory duties (GDPR, PCI, contractual) – involve counsel/security leadership early.' },
    ],
  },
  {
    id: 'g-hunt',
    category: 'detect',
    title: 'Hunt for signs of exploitation (logs, files, processes)',
    snippet: 'Start at 2026-10-21 07:43 UTC when Cloudflare saw the first attacks. Look for the marker, OOM errors, worker crashes, odd cookies and new files.',
    when: [],
    sections: [
      { code: `# Marker in logged request bodies / WAF logs (needs body logging)
zgrep -h 'PHP_SESSION_UPLOAD_PROGRESS' /var/log/nginx/*access* /var/log/apache2/*access* 2>/dev/null

# PHP/FPM: out-of-memory errors and crashing workers
grep -E 'Allowed memory size|exited on signal|SIGSEGV' /var/log/php*-fpm.log /var/log/apache2/error.log 2>/dev/null

# New or modified PHP files in web roots since disclosure
find /var/www -type f -name '*.php' -newermt '2026-10-21' -ls

# Unexpected child processes of PHP workers
ps -eo pid,ppid,user,cmd --forest | grep -B1 -A3 -E 'php-fpm|apache2|httpd'` },
      { text: 'Other signals (Wiz/Sansec): bursts of multipart POSTs to PHP endpoints from unfamiliar sources, repeated HTTP 500s, unusually large or malformed `PHPSESSID` response cookies (possible memory disclosure), unexplained FPM worker churn, changes to PHP/OPcache configuration, new outbound connections from web hosts.' },
      { text: 'Application logs often show little: these bugs act below the app layer. Rely on web server, WAF, FPM and EDR/process telemetry.' },
    ],
  },
  {
    id: 'g-sigma',
    category: 'detect',
    title: 'Deploy the repo\'s detection rules (Suricata, ModSecurity, OpenResty, Sigma)',
    snippet: 'Quick-start steps for each engine, and which rule IDs matter most.',
    when: [],
    sections: [
      { code: `# Suricata
cp php2shell.rules /etc/suricata/rules/   # add under rule-files: in suricata.yaml
suricatasc -c reload-rules

# ModSecurity (Apache/nginx)
cp modsecurity.conf /etc/modsecurity.d/php2shell.conf   # include it, then reload web server

# OpenResty / nginx + Lua
# load php2shell.lua and call check() from an access_by_lua_block

# Corelight Zeek
zkg install https://github.com/corelight/php2shell-detect` },
      { text: 'Deploy both request-side rules (e.g. SID 2026100 upload-progress marker; 2026101 session ID in form field; 2026102/2026103 code/serialized object in filename) and response-side rules (2026110 OOM error, 2026111 session-destruction failure, 2026112 abnormal session cookie length). Network rules need decrypted HTTP; WAF body limits apply.' },
      { text: 'Treat version-banner rules (e.g. 2026116) as inventory hints only – banners can be hidden or reflect backports.' },
    ],
  },
  {
    id: 'g-brief',
    category: 'read',
    title: 'Briefing for leadership: what to tell the business',
    snippet: 'Five lines you can paste into an incident channel or exec update.',
    when: [],
    sections: [
      { code: `What: Two critical (CVSS 9.2) flaws in the PHP engine (CVE-2026-109618, CVE-2026-109619) allow unauthenticated remote code execution and memory disclosure on PHP 5.4 through 8.5.11.
Who is exposed: any internet-facing PHP site/app, regardless of CMS or app code. PHP 8.1 and older get no upstream fix.
Fix: upgrade PHP to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 or later (or a vendor build whose changelog lists both CVEs), then restart workers/redeploy images.
Interim: WAF rules, disable session.upload_progress, block multipart on non-upload routes, restrict outbound traffic.
Ask: owner per system, patch ETA today for internet-facing systems, and secrets rotation for anything suspected exposed.` },
    ],
  },
];

export function getResources() {
  return {
    advisory: {
      name: ADVISORY.name,
      disclosed: ADVISORY.disclosed,
      cves: ADVISORY.cves,
      fixed: ADVISORY.fixed,
      source: ADVISORY.repo,
    },
    items: [
      ...guides.map((g) => ({ kind: 'guide', ...g })),
      ...links.map((l) => ({ kind: 'link', ...l })),
    ],
  };
}
