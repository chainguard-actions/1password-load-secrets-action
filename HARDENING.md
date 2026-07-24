<!-- markdownlint-disable -->

# Hardening Report: 1Password--load-secrets-action/v4.1.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **1Password--load-secrets-action/v4.1.1** was hardened automatically. 7 finding(s) were identified and resolved across 2 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The `check-external-pr` job's `run:` block in test-e2e.yml directly interpolates multiple `github.*` context expressions inside shell commands without routing them through `env:` variables. Offending lines include: `echo "Event name: ${{ github.event_name }}"`, `if [ "${{ github.event_name }}" == "pull_request" ]`, `echo "PR head repo: ${{ github.event.pull_request.head.repo.full_name }}"`, `if [ "${{ github.actor }}" == "dependabot[bot]" ]`, `elif [ "${{ github.event.pull_request.head.repo.full_name }}" != "${{ github.repository }}" ]`, `echo "ref=${{ github.event.pull_request.head.sha }}" >> $GITHUB_OUTPUT`, `SHA_PARAM="${{ github.event.client_payload.slash_command.args.named.sha }}"`, `PR_HEAD_SHA="${{ github.event.client_payload.pull_request.head.sha }}"`, `elif [ "${{ github.event_name }}" == "push" ]`, `echo "ref=${{ github.sha }}" >> $GITHUB_OUTPUT`, and `echo "condition=skip (unknown event type: ${{ github.event_name }})"`. These allow an attacker to inject arbitrary shell commands via pull_request or repository_dispatch events.

Locations:

- `.github/workflows/test-e2e.yml:34`
- `.github/workflows/test-e2e.yml:35`
- `.github/workflows/test-e2e.yml:37`
- `.github/workflows/test-e2e.yml:39`
- `.github/workflows/test-e2e.yml:40`
- `.github/workflows/test-e2e.yml:44`
- `.github/workflows/test-e2e.yml:49`
- `.github/workflows/test-e2e.yml:53`
- `.github/workflows/test-e2e.yml:54`
- `.github/workflows/test-e2e.yml:66`
- `.github/workflows/test-e2e.yml:69`
- `.github/workflows/test-e2e.yml:72`

### script-injection (severity: high)

Sub-rule (a): Multiple `run:` blocks in e2e-tests.yml directly interpolate `${{ matrix.version }}`, `${{ matrix.versionPath }}`, `${{ matrix.channel }}`, `${{ matrix.fallbackKey }}`, and `${{ steps.expected.outputs.version }}` inside shell commands. Offending examples: `expected="${{ matrix.version }}"` (test-install job), `version=$(curl -s https://app-updates.agilebits.com/latest | jq -r '${{ matrix.versionPath }}')` and `expected="${{ steps.expected.outputs.version }}"` (test-docker-hub-fallback job), `src.match(/ReleaseChannel.${{ matrix.fallbackKey }}]` and `expected="${{ steps.expected.outputs.version }}"` (test-baked-in-fallback job). Matrix values and step outputs are workflow-controllable and must not be interpolated directly into shell.

Locations:

- `.github/workflows/e2e-tests.yml:296`
- `.github/workflows/e2e-tests.yml:340`
- `.github/workflows/e2e-tests.yml:355`
- `.github/workflows/e2e-tests.yml:380`
- `.github/workflows/e2e-tests.yml:400`
- `.github/workflows/e2e-tests.yml:420`

### github-env-injection (severity: high)

The `check-external-pr` job's `run:` block in test-e2e.yml writes `github.*` context values directly to `$GITHUB_OUTPUT` without the required sanitization step (`printf '%s' ... | tr -d '\n\r'`). Specifically: `echo "ref=${{ github.event.pull_request.head.sha }}" >> $GITHUB_OUTPUT` and `echo "ref=${{ github.sha }}" >> $GITHUB_OUTPUT`. An attacker who controls the PR head SHA could inject additional key=value pairs into GITHUB_OUTPUT, potentially overwriting outputs consumed by downstream jobs.

Locations:

- `.github/workflows/test-e2e.yml:49`
- `.github/workflows/test-e2e.yml:69`

### unpinned-uses (severity: high)

check-fallback-versions.yml uses mutable tag refs instead of full 40-character SHA pins: `actions/checkout@v6` and `actions/setup-node@v6`. These are vulnerable to supply-chain attacks if the referenced action tags are moved.

Locations:

- `.github/workflows/check-fallback-versions.yml:9`
- `.github/workflows/check-fallback-versions.yml:10`

### unpinned-uses (severity: high)

e2e-tests.yml uses mutable tag refs (`@v6`) instead of full 40-character SHA pins in multiple jobs. Unpinned references: `actions/checkout@v6` and `actions/setup-node@v6` appear in the `test-service-account-smoke`, `test-install`, `test-docker-hub-fallback`, and `test-baked-in-fallback` jobs.

Locations:

- `.github/workflows/e2e-tests.yml:163`
- `.github/workflows/e2e-tests.yml:170`
- `.github/workflows/e2e-tests.yml:218`
- `.github/workflows/e2e-tests.yml:225`
- `.github/workflows/e2e-tests.yml:310`
- `.github/workflows/e2e-tests.yml:317`
- `.github/workflows/e2e-tests.yml:365`
- `.github/workflows/e2e-tests.yml:372`

### missing-permissions (severity: medium)

check-fallback-versions.yml has no top-level `permissions:` key and its only job (`check-fallback-versions`) also has no job-level `permissions:` key. Without explicit permissions, the workflow inherits the default repository permissions (which may include `contents: write` and other broad scopes), violating the principle of least privilege.

Locations:

- `.github/workflows/check-fallback-versions.yml:1`

### missing-permissions (severity: medium)

e2e-tests.yml has no top-level `permissions:` key and none of its jobs (`test-service-account`, `test-service-account-smoke`, `test-connect`, `test-install`, `test-docker-hub-fallback`, `test-baked-in-fallback`) define a job-level `permissions:` key. Without explicit permissions, all jobs inherit the default repository permissions, which may be overly broad.

Locations:

- `.github/workflows/e2e-tests.yml:1`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, unpinned-uses, missing-permissions

**Notes:**

Fixed all 7 findings across 3 workflow files:

1. test-e2e.yml (script-injection + github-env-injection): Moved all ${{ github.* }} expressions from the check-external-pr run: block into the step's env: block as named variables (EVENT_NAME, REPOSITORY, PR_HEAD_REPO, ACTOR, PR_HEAD_SHA, DISPATCH_SHA_PARAM, DISPATCH_PR_HEAD_SHA, GITHUB_SHA_VAL, REF_NAME). Added printf '%s' ... | tr -d '\n\r' sanitization before writing SHA values to $GITHUB_OUTPUT.

2. e2e-tests.yml (script-injection): Moved ${{ matrix.version }}, ${{ matrix.versionPath }}, ${{ matrix.channel }}, ${{ matrix.fallbackKey }}, and ${{ steps.expected.outputs.version }} from run: blocks into env: blocks (EXPECTED_VERSION, VERSION_PATH, MATRIX_CHANNEL, FALLBACK_KEY). The node -e script for baked-in fallback now uses process.env.FALLBACK_KEY instead of interpolating the matrix value directly.

3. e2e-tests.yml (unpinned-uses): Pinned all 8 occurrences of actions/checkout@v6 and actions/setup-node@v6 to full SHA hashes (d23441a48e516b6c34aea4fa41551a30e30af803 and 249970729cb0ef3589644e2896645e5dc5ba9c38 respectively).

4. check-fallback-versions.yml (unpinned-uses): Pinned actions/checkout@v6 and actions/setup-node@v6 to full SHA hashes.

5. check-fallback-versions.yml (missing-permissions): Added top-level permissions: contents: read.

6. e2e-tests.yml (missing-permissions): Added top-level permissions: contents: read.

### Iteration 2

**Fixes applied:** missing-permissions

**Notes:**

Added a top-level `permissions: contents: read` block to `.github/workflows/test-e2e.yml`. This restricts the default token permissions for the `check-external-pr` and `e2e` jobs to the minimum needed (read-only access to repository contents). The `comment-pr` job already had its own job-level `permissions: pull-requests: write` block which continues to override the top-level for that job.

