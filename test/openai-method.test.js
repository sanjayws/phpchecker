import { test } from 'node:test';
import assert from 'node:assert/strict';
import { openaiPatchStatus, openaiPickVersion } from '../src/openai-method.js';

// Expected values follow upstream php2shell-checker's documented behaviour
// (https://github.com/openai/php2shell-checker, Apache-2.0).
test('openaiPatchStatus', () => {
  assert.equal(openaiPatchStatus('8.3.35'), 'vulnerable');
  assert.equal(openaiPatchStatus('8.3.36'), 'ok');
  assert.equal(openaiPatchStatus('8.5.11'), 'vulnerable');
  assert.equal(openaiPatchStatus('8.5.12'), 'ok');
  assert.equal(openaiPatchStatus('7.4.33'), 'vulnerable');
  assert.equal(openaiPatchStatus('5.6.40'), 'vulnerable');
  assert.equal(openaiPatchStatus('8.5.12-dev'), 'unknown'); // pre-release of the next patch
  assert.equal(openaiPatchStatus('8.4.27RC1'), 'unknown'); // upstream's pattern requires a -/+/~ separator, so this isn't parsed
  assert.equal(openaiPatchStatus('8.4.27-rc1'), 'unknown');
  assert.equal(openaiPatchStatus('8.6.0'), 'unknown'); // unlisted branch
  assert.equal(openaiPatchStatus('7.4'), 'unknown'); // no patch component
  assert.equal(openaiPatchStatus(null), 'unknown');
});

test('openaiPickVersion never lets an ok banner hide a vulnerable one', () => {
  const r = openaiPickVersion([{ name: 'Server', value: 'Apache PHP/8.5.12' }, { name: 'X-Powered-By', value: 'PHP/7.4.33' }]);
  assert.equal(r.version, '7.4.33');
  assert.equal(r.status, 'vulnerable');
  assert.equal(openaiPickVersion([]).status, 'unknown');
});
