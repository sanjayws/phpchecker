# Third-party notices

## OpenAI php2shell-checker

PHPChecker's second detection check (`src/openai-method.js`, run on every scan) and its
pre-release / unlisted-branch rules (`src/version.js`) re-implement the method of
**php2shell-checker** by OpenAI, and `test/version.test.js` uses that project's
"vulnerable through" version table as an independent test oracle.

- Project: https://github.com/openai/php2shell-checker
- Copyright: OpenAI
- License: Apache License 2.0 — https://www.apache.org/licenses/LICENSE-2.0

No source files from that project are included; the method and version table are
re-implemented and credited here. PHPChecker is not affiliated with or endorsed by OpenAI.
