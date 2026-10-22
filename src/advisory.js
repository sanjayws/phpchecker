// Single source of truth for the advisory facts. Update here when upstream changes.
// Source: https://github.com/ikow/php2shell-poc (README) and the PHP advisory it links.
export const ADVISORY = {
  name: 'php2shell',
  disclosed: '2026-10-21',
  cves: [
    {
      id: 'CVE-2026-109618',
      ghsa: 'GHSA-w8hw-w9fx-j79w',
      cvss: 9.2,
      title: 'Out-of-memory handling vulnerability',
      description:
        'An out-of-memory handling vulnerability that could allow an unauthenticated remote attacker to execute arbitrary code on affected systems.',
      summary: 'Out-of-memory handling via longjmp() leaves Zend engine state invalid.',
    },
    {
      id: 'CVE-2026-109619',
      ghsa: 'GHSA-6wmf-4rv5-p3rp',
      cvss: 9.2,
      title: 'Use-after-free vulnerability',
      description:
        'A use-after-free vulnerability that could allow an unauthenticated remote attacker to execute arbitrary code on affected systems.',
      summary: 'Stale global state across PHP-FPM worker requests leads to use-after-free.',
    },
  ],
  affectedFrom: { major: 5, minor: 4, patch: 0 },
  lastAffected: '8.5.11',
  // First fixed patch release per supported branch.
  fixed: { '8.2': 35, '8.3': 36, '8.4': 27, '8.5': 12 },
  // Branches below this have no upstream fix (EOL).
  oldestSupportedBranch: { major: 8, minor: 2 },
  repo: 'https://github.com/ikow/php2shell-poc',
};
