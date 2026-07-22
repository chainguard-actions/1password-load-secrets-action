<!-- markdownlint-disable -->

# Hardening Report: 1password--load-secrets-action/v4.0.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **1password--load-secrets-action/v4.0.1** was hardened automatically. 4 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'Check if PR is from external contributor' step in test-e2e.yml directly interpolates multiple github context expressions inside run: shell commands. This allows an attacker to inject arbitrary shell commands via pull request metadata. Offending lines include: `if [ "${{ github.event_name }}" == "pull_request" ]`, `if [ "${{ github.actor }}" == "dependabot[bot]" ]`, `elif [ "${{ github.event.pull_request.head.repo.full_name }}" != "${{ github.repository }}" ]`, `SHA_PARAM="${{ github.event.client_payload.slash_command.args.named.sha }}"`, `PR_HEAD_SHA="${{ github.event.client_payload.pull_request.head.sha }}"`, `echo "ref=${{ github.event.pull_request.head.sha }}" >> $GITHUB_OUTPUT`, `echo "ref=${{ github.sha }}" >> $GITHUB_OUTPUT`, and `echo "condition=skip (unknown event type: ${{ github.event_name }})"`. All these values should be passed via env: variables and then double-quoted in the shell script.

Locations:

- `.github/workflows/test-e2e.yml:32`

### github-env-injection (severity: high)

The 'Check if PR is from external contributor' step in test-e2e.yml writes github context values directly to $GITHUB_OUTPUT without sanitization (no `printf '%s' ... | tr -d '\n\r'` step). Specifically: (1) `echo "ref=${{ github.event.pull_request.head.sha }}" >> $GITHUB_OUTPUT` writes an unsanitized github expression directly; (2) `echo "ref=$PR_HEAD_SHA" >> $GITHUB_OUTPUT` writes $PR_HEAD_SHA which was set from `${{ github.event.client_payload.pull_request.head.sha }}` without sanitization; (3) `echo "ref=${{ github.sha }}" >> $GITHUB_OUTPUT` writes an unsanitized github expression directly. An attacker could inject newlines into these values to poison GITHUB_OUTPUT.

Locations:

- `.github/workflows/test-e2e.yml:46`
- `.github/workflows/test-e2e.yml:59`
- `.github/workflows/test-e2e.yml:66`

### unpinned-uses (severity: high)

Multiple workflow files reference GitHub Actions using mutable version tags (@v6) instead of pinned full-length SHA commit hashes. This exposes the workflow to supply-chain attacks if the tag is moved. Failing references in e2e-tests.yml: `actions/checkout@v6` (line 37), `actions/setup-node@v6` (line 42), `actions/checkout@v6` (line 130), `actions/setup-node@v6` (line 135). Failing references in lint-and-test.yml: `actions/checkout@v6` (line 12), `actions/setup-node@v6` (line 19).

Locations:

- `.github/workflows/e2e-tests.yml:37`
- `.github/workflows/e2e-tests.yml:42`
- `.github/workflows/e2e-tests.yml:130`
- `.github/workflows/e2e-tests.yml:135`
- `.github/workflows/lint-and-test.yml:12`
- `.github/workflows/lint-and-test.yml:19`

### missing-permissions (severity: medium)

Three workflow files have no top-level `permissions:` key and contain jobs that also lack job-level `permissions:` blocks, meaning those jobs run with the default (overly broad) GITHUB_TOKEN permissions. In e2e-tests.yml, neither `test-service-account` nor `test-connect` jobs have permissions defined. In lint-and-test.yml, the `lint-and-test` job has no permissions defined. In test-e2e.yml, the `check-external-pr` and `e2e` jobs have no permissions defined (only `comment-pr` has job-level permissions).

Locations:

- `.github/workflows/e2e-tests.yml:1`
- `.github/workflows/lint-and-test.yml:1`
- `.github/workflows/test-e2e.yml:1`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, missing-permissions

**Notes:**

Fixed all four findings:
1. script-injection (test-e2e.yml): Moved all ${{ github.* }} expressions from run: shell commands into the step's env: block, referencing them as plain env vars ($EVENT_NAME, $ACTOR, $REPOSITORY, $PR_HEAD_REPO, $PR_HEAD_SHA, $SLASH_CMD_SHA, $DISPATCH_PR_HEAD_SHA, $GITHUB_SHA_VAL).
2. github-env-injection (test-e2e.yml): All values written to $GITHUB_OUTPUT are now sanitized with `safe_ref=$(printf '%s' "$VAR" | tr -d '\n\r')` before writing.
3. unpinned-uses: Pinned actions/checkout@v6 to SHA d23441a48e516b6c34aea4fa41551a30e30af803 and actions/setup-node@v6 to SHA 249970729cb0ef3589644e2896645e5dc5ba9c38 in both e2e-tests.yml (4 occurrences) and lint-and-test.yml (2 occurrences).
4. missing-permissions: Added `permissions: {}` at top level of test-e2e.yml; added `permissions: contents: read` at job level for test-service-account and test-connect in e2e-tests.yml, and for lint-and-test in lint-and-test.yml.

