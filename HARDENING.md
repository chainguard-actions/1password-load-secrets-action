<!-- markdownlint-disable -->

# Hardening Report: 1Password--load-secrets-action/v5.0.0-beta.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **1Password--load-secrets-action/v5.0.0-beta.1** was hardened automatically. 4 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

The `check-external-pr` job's `run:` block in test-e2e.yml directly interpolates multiple `${{ github.* }}` expressions inside shell commands (rule a). Attacker-controllable values such as `${{ github.event.pull_request.head.repo.full_name }}`, `${{ github.actor }}`, `${{ github.event.client_payload.slash_command.args.named.sha }}`, `${{ github.event.client_payload.pull_request.head.sha }}`, `${{ github.event_name }}`, `${{ github.repository }}`, `${{ github.event.pull_request.head.sha }}`, and `${{ github.sha }}` are substituted directly into shell command strings before the shell parses them. A malicious value containing shell metacharacters (`;`, `|`, `$(...)`, etc.) could execute arbitrary commands on the runner.

Locations:

- `.github/workflows/test-e2e.yml:33`
- `.github/workflows/test-e2e.yml:34`
- `.github/workflows/test-e2e.yml:36`
- `.github/workflows/test-e2e.yml:38`
- `.github/workflows/test-e2e.yml:40`
- `.github/workflows/test-e2e.yml:43`
- `.github/workflows/test-e2e.yml:47`
- `.github/workflows/test-e2e.yml:48`
- `.github/workflows/test-e2e.yml:57`
- `.github/workflows/test-e2e.yml:63`

### github-env-injection (severity: high)

The `check-external-pr` job's `run:` block in test-e2e.yml writes values derived from `${{ github.* }}` context directly to `$GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). Specifically: (1) `echo "ref=${{ github.event.pull_request.head.sha }}" >> $GITHUB_OUTPUT` writes a raw github context value; (2) `echo "ref=$PR_HEAD_SHA" >> $GITHUB_OUTPUT` writes `PR_HEAD_SHA` which was set from `${{ github.event.client_payload.pull_request.head.sha }}`; (3) `echo "ref=${{ github.sha }}" >> $GITHUB_OUTPUT` writes another raw github context value. A newline-containing value could inject additional key=value pairs into GITHUB_OUTPUT, poisoning subsequent steps.

Locations:

- `.github/workflows/test-e2e.yml:43`
- `.github/workflows/test-e2e.yml:54`
- `.github/workflows/test-e2e.yml:57`

### unpinned-uses (severity: high)

Multiple workflow files reference GitHub Actions by mutable version tags instead of immutable 40-character commit SHAs. This exposes the workflow to supply-chain attacks if the tag is moved to a malicious commit. Unpinned references found:
- `actions/checkout@v6` (tag, not a SHA)
- `actions/setup-node@v6` (tag, not a SHA)
These appear in both e2e-tests.yml and lint-and-test.yml.

Locations:

- `.github/workflows/e2e-tests.yml:44`
- `.github/workflows/e2e-tests.yml:48`
- `.github/workflows/e2e-tests.yml:131`
- `.github/workflows/e2e-tests.yml:135`
- `.github/workflows/e2e-tests.yml:218`
- `.github/workflows/e2e-tests.yml:222`
- `.github/workflows/lint-and-test.yml:11`
- `.github/workflows/lint-and-test.yml:17`

### missing-permissions (severity: medium)

Three workflow files have no top-level `permissions:` block and contain jobs that also lack job-level `permissions:` blocks. Without explicit permissions, GitHub Actions defaults to the repository's default token permissions (which may be `read-all` or `write-all` depending on org settings), violating the principle of least privilege.

- `e2e-tests.yml`: No top-level permissions; `test-service-account` and `test-connect` jobs have no `permissions:` key (only `test-workload-identity` has job-level permissions).
- `lint-and-test.yml`: No top-level permissions; the `lint-and-test` job has no `permissions:` key.
- `test-e2e.yml`: No top-level permissions; the `check-external-pr` and `e2e` jobs have no `permissions:` key (only `comment-pr` has job-level permissions).

Locations:

- `.github/workflows/e2e-tests.yml:1`
- `.github/workflows/lint-and-test.yml:1`
- `.github/workflows/test-e2e.yml:1`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, missing-permissions

**Notes:**

Fixed all four findings across three workflow files:

1. **script-injection** (test-e2e.yml lines 33-63): Moved all ${{ github.* }} expressions (github.event_name, github.repository, github.event.pull_request.head.repo.full_name, github.actor, github.event.client_payload.slash_command.args.named.sha, github.event.client_payload.pull_request.head.sha, github.event.pull_request.head.sha, github.sha) into the step's `env:` block. Shell script now references plain environment variables.

2. **github-env-injection** (test-e2e.yml lines 43, 54, 57): All three GITHUB_OUTPUT writes that used github context values now sanitize via `safe_ref=$(printf '%s' "$VAR" | tr -d '\n\r')` before writing to $GITHUB_OUTPUT.

3. **unpinned-uses** (e2e-tests.yml, lint-and-test.yml): Pinned actions/checkout@v6 → @d23441a48e516b6c34aea4fa41551a30e30af803 and actions/setup-node@v6 → @249970729cb0ef3589644e2896645e5dc5ba9c38 in all 8 locations across both files.

4. **missing-permissions** (all three files): Added `permissions: {}` at top level of e2e-tests.yml, lint-and-test.yml, and test-e2e.yml. Added `permissions: contents: read` to test-service-account, test-connect (e2e-tests.yml), lint-and-test (lint-and-test.yml), and check-external-pr (test-e2e.yml) jobs. Added `permissions: {}` to the e2e reusable workflow call job.

