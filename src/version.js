import { ADVISORY } from './advisory.js';

// Distro package suffixes inside the PHP version string ("8.1.2-1ubuntu2.14", "7.4.33-1+deb11u5", "8.0.30.el9").
const PKG_SUFFIXES = [
  [/ubuntu/i, 'ubuntu'],
  [/deb\d+u\d+|[+~]deb\d+|debian/i, 'debian'],
  [/\.el\d+/i, 'rhel'],
  [/\.amzn\d+/i, 'amazon linux'],
  [/\.fc\d+/i, 'fedora'],
  [/suse|\.sle/i, 'suse'],
];
// Third-party repos that ship upstream releases as-is: their version number is authoritative.
const UPSTREAM_REPACKAGERS = /sury|remi/i;
// Vendors that backport fixes but keep the plain upstream version in X-Powered-By.
const PLAIN_VERSION_BACKPORTERS = /red hat|rhel|centos|rocky|alma|amazon|suse|cloudlinux/i;

/** "PHP/8.1.2-1ubuntu2.14 OpenSSL/3" -> "8.1.2-1ubuntu2.14". Only the PHP token, never other products' versions. */
export function extractPhpToken(banner) {
  const m = typeof banner === 'string' && banner.match(/php\/?\s*(\d+\.\d+(?:\.\d+)?[^\s,;()]*)/i);
  return m ? m[1].slice(0, 80) : null;
}

/**
 * Name of the vendor whose build may carry a backported fix (so the version number alone
 * cannot prove exposure), or null when the version is authoritative.
 */
export function detectBackport(phpToken, server) {
  const tok = phpToken || '';
  if (UPSTREAM_REPACKAGERS.test(tok)) return null;
  for (const [re, name] of PKG_SUFFIXES) if (re.test(tok)) return name;
  // Plain upstream version: only RHEL-family style vendors still backport silently.
  // A plain version behind "(Debian)"/"(Ubuntu)" is usually a source/Docker build.
  const serverToken = (typeof server === 'string' && server.match(/\(([^)]+)\)/)?.[1]) || '';
  const m = serverToken.match(PLAIN_VERSION_BACKPORTERS);
  return m && !/[-+~]/.test(tok) ? m[0].toLowerCase() : null;
}

/** Pull the first `major.minor[.patch]` out of a version string like "8.1.2-1ubuntu2.14". */
export function parseVersion(input) {
  if (typeof input !== 'string') return null;
  const m = input.match(/(\d{1,2})\.(\d{1,2})(?:\.(\d{1,3}))?/);
  if (!m) return null;
  return {
    major: Number(m[1]),
    minor: Number(m[2]),
    patch: m[3] === undefined ? null : Number(m[3]),
    raw: input.trim().slice(0, 120),
  };
}

/**
 * Compare a parsed version with the advisory.
 * status: vulnerable | vulnerable_eol | patched | unlisted | incomplete
 */
export function assessVersion(v) {
  const label = v.patch === null ? `${v.major}.${v.minor}` : `${v.major}.${v.minor}.${v.patch}`;
  const branch = `${v.major}.${v.minor}`;
  const a = ADVISORY.affectedFrom;
  const oldest = ADVISORY.oldestSupportedBranch;

  const base = { version: label, branch, fixedIn: null };

  if (v.major > 8 || (v.major === 8 && v.minor > 5)) {
    return { ...base, status: 'patched', summary: `PHP ${label} is newer than the affected range.` };
  }
  if (v.major < a.major || (v.major === a.major && v.minor < a.minor)) {
    return {
      ...base,
      status: 'unlisted',
      summary: `PHP ${label} predates the advisory's affected range (5.4+), but it is long unsupported and carries many other known flaws.`,
    };
  }
  const supported = v.major > oldest.major || (v.major === oldest.major && v.minor >= oldest.minor);
  if (!supported) {
    return {
      ...base,
      status: 'vulnerable_eol',
      summary: `PHP ${branch} is in the affected range and end-of-life: upstream ships no fix. Upgrade to 8.2+ or get a vendor backport.`,
    };
  }
  const fixedPatch = ADVISORY.fixed[branch];
  const fixedIn = `${branch}.${fixedPatch}`;
  if (v.patch === null) {
    return {
      ...base,
      fixedIn,
      status: 'incomplete',
      summary: `Only the branch (${branch}) is known. Fixed in ${fixedIn}; check the exact patch level.`,
    };
  }
  if (v.patch >= fixedPatch) {
    return { ...base, fixedIn, status: 'patched', summary: `PHP ${label} includes the fix (first fixed: ${fixedIn}).` };
  }
  return {
    ...base,
    fixedIn,
    status: 'vulnerable',
    summary: `PHP ${label} is affected. Upgrade to ${fixedIn} or later.`,
  };
}

/** Map an assessment (+ distro hint) to a user-facing verdict. */
export function verdictFor(assessment, distro) {
  switch (assessment.status) {
    case 'vulnerable':
    case 'vulnerable_eol':
      return distro ? 'verify' : 'vulnerable';
    case 'incomplete':
    case 'unlisted':
      return 'verify';
    case 'patched':
      return 'patched';
    default:
      return 'unknown';
  }
}
