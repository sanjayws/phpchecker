import { test } from 'node:test';
import assert from 'node:assert/strict';
import { assessVersion, parseVersion, verdictFor, detectBackport, extractPhpToken } from '../src/version.js';
import { fingerprintOS, parseServer } from '../src/fingerprint.js';

const assess = (s) => assessVersion(parseVersion(s));

test('fixed releases are patched, one below is vulnerable', () => {
  for (const [ok, bad] of [['8.2.35', '8.2.34'], ['8.3.36', '8.3.35'], ['8.4.27', '8.4.26'], ['8.5.12', '8.5.11']]) {
    assert.equal(assess(ok).status, 'patched', ok);
    assert.equal(assess(bad).status, 'vulnerable', bad);
  }
});

test('EOL branches are vulnerable without a fix', () => {
  for (const v of ['5.4.0', '7.4.33', '8.0.30', '8.1.2']) assert.equal(assess(v).status, 'vulnerable_eol', v);
});

test('older than affected range and newer than 8.5', () => {
  assert.equal(assess('5.3.29').status, 'unlisted');
  assert.equal(assess('8.6.0').status, 'patched');
  assert.equal(assess('9.0.1').status, 'patched');
});

test('branch-only versions need verification', () => {
  assert.equal(assess('8.3').status, 'incomplete');
});

test('extractPhpToken takes only the PHP version, not other products', () => {
  assert.equal(extractPhpToken('PHP/8.1.2-1ubuntu2.14'), '8.1.2-1ubuntu2.14');
  assert.equal(extractPhpToken('Apache/2.4.52 (Ubuntu) PHP/8.1.2 OpenSSL/3.0.2'), '8.1.2');
  assert.equal(extractPhpToken('PleskLin 18.0.5, PHP/7.4.33'), '7.4.33');
  assert.equal(extractPhpToken('PHP/7.4.33 (php-fpm)'), '7.4.33');
  assert.equal(extractPhpToken('ASP.NET'), null);
});

test('backport detection', () => {
  assert.equal(detectBackport('8.1.2-1ubuntu2.14', null), 'ubuntu');
  assert.equal(detectBackport('7.4.33-1+deb11u5', null), 'debian');
  assert.equal(detectBackport('8.0.30', 'Apache/2.4.57 (Red Hat Enterprise Linux)'), 'red hat');
  // Plain upstream version behind a Debian/Ubuntu Apache is usually the official Docker image.
  assert.equal(detectBackport('8.3.30', 'Apache/2.4.62 (Debian)'), null);
  // Surý/Remi ship upstream releases as-is: version is authoritative.
  assert.equal(detectBackport('8.3.30-1+ubuntu22.04.1+deb.sury.org+1', null), null);
  assert.equal(verdictFor(assess('8.1.2'), 'ubuntu'), 'verify');
  assert.equal(verdictFor(assess('8.3.30'), null), 'vulnerable');
});

test('OS fingerprinting', () => {
  assert.equal(fingerprintOS({ phpBanner: '8.3.6-0ubuntu0.24.04.5' }).release, '24.04');
  assert.equal(fingerprintOS({ phpBanner: '8.3.30-1+ubuntu22.04.1+deb.sury.org+1' }).release, '22.04');
  assert.equal(fingerprintOS({ phpBanner: '8.1.2-1ubuntu2.14' }).release, '22.04');
  assert.equal(fingerprintOS({ phpBanner: '7.4.33-1+deb11u3' }).release, '11');
  assert.equal(fingerprintOS({ server: 'Apache/2.4.52 (Ubuntu)' }).release, '22.04');
  assert.equal(fingerprintOS({ server: 'Microsoft-IIS/10.0' }).name, 'Windows Server');
  assert.equal(fingerprintOS({ server: 'nginx' }), null);
});

test('parseServer', () => {
  const s = parseServer('Apache/2.4.52 (Ubuntu) PHP/8.1.2 OpenSSL/3.0.2');
  assert.equal(s.product, 'Apache');
  assert.equal(s.version, '2.4.52');
  assert.equal(s.token, 'Ubuntu');
  assert.deepEqual(s.modules, ['PHP/8.1.2', 'OpenSSL/3.0.2']);
});
