<!-- markdownlint-disable -->

# Hardening Report: 1Password--load-secrets-action/v5.0.0

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **1Password--load-secrets-action/v5.0.0** was hardened automatically. 7 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Rule (a) violation: The 'Check if PR is from external contributor' run: block in test-e2e.yml directly interpolates multiple github.* context values into shell commands without routing through env: variables. Offending lines include: `if [ "${{ github.event_name }}" == "pull_request" ]`, `if [ "${{ github.actor }}" == "dependabot[bot]" ]`, `elif [ "${{ github.event.pull_request.head.repo.full_name }}" != "${{ github.repository }}" ]`, `echo "ref=${{ github.event.pull_request.head.sha }}" >> $GITHUB_OUTPUT`, `SHA_PARAM="${{ github.event.client_payload.slash_command.args.named.sha }}"`, `PR_HEAD_SHA="${{ github.event.client_payload.pull_request.head.sha }}"`, `echo "ref=${{ github.sha }}" >> $GITHUB_OUTPUT`. An attacker controlling PR metadata (e.g. head.repo.full_name, actor) can inject arbitrary shell commands.

Locations:

- `.github/workflows/test-e2e.yml:37`

### script-injection (severity: high)

Rule (a) violation: Multiple run: blocks in e2e-tests.yml directly interpolate ${{ matrix.* }} and ${{ steps.*.outputs.* }} context values into shell commands. Offending patterns include: `expected="${{ matrix.version }}"` (test-install job), `jq -r '${{ matrix.versionPath }}'` and `echo "Expected ${{ matrix.channel }} version: $version"` (test-docker-hub-fallback job), `src.match(/ReleaseChannel.${{ matrix.fallbackKey }}].../)` and `console.error('...for ${{ matrix.fallbackKey }}')` (test-baked-in-fallback job), and `expected="${{ steps.expected.outputs.version }}"` (both test-docker-hub-fallback and test-baked-in-fallback jobs). Matrix values and step outputs are workflow-controllable and must not be interpolated directly into run: scripts.

Locations:

- `.github/workflows/e2e-tests.yml:296`
- `.github/workflows/e2e-tests.yml:340`
- `.github/workflows/e2e-tests.yml:388`
- `.github/workflows/e2e-tests.yml:406`

### unpinned-uses (severity: high)

The following uses: references are pinned to mutable version tags rather than immutable 40-character commit SHAs, making them vulnerable to supply-chain attacks: `actions/checkout@v6` and `actions/setup-node@v6`.

Locations:

- `.github/workflows/check-fallback-versions.yml:10`
- `.github/workflows/check-fallback-versions.yml:11`

### unpinned-uses (severity: high)

Multiple jobs in e2e-tests.yml use mutable tag-pinned references instead of full 40-character commit SHAs: `actions/checkout@v6` and `actions/setup-node@v6` appear in the test-service-account-smoke, test-install, test-docker-hub-fallback, test-baked-in-fallback, and test-workload-identity jobs.

Locations:

- `.github/workflows/e2e-tests.yml:152`
- `.github/workflows/e2e-tests.yml:158`
- `.github/workflows/e2e-tests.yml:270`
- `.github/workflows/e2e-tests.yml:276`
- `.github/workflows/e2e-tests.yml:310`
- `.github/workflows/e2e-tests.yml:316`
- `.github/workflows/e2e-tests.yml:358`
- `.github/workflows/e2e-tests.yml:364`
- `.github/workflows/e2e-tests.yml:430`
- `.github/workflows/e2e-tests.yml:436`

### missing-permissions (severity: medium)

check-fallback-versions.yml has no top-level permissions: block and its only job (check-fallback-versions) also has no job-level permissions: block. Without explicit permissions, the workflow inherits the default repository permissions, which may be overly broad.

Locations:

- `.github/workflows/check-fallback-versions.yml:1`

### missing-permissions (severity: medium)

test-e2e.yml has no top-level permissions: block. The check-external-pr job has no job-level permissions: block (only the comment-pr job has job-level permissions). Without explicit permissions on the check-external-pr job, it inherits the default repository permissions.

Locations:

- `.github/workflows/test-e2e.yml:1`

### missing-permissions (severity: medium)

e2e-tests.yml has no top-level permissions: block. The jobs test-service-account, test-service-account-smoke, test-connect, test-install, test-docker-hub-fallback, and test-baked-in-fallback all lack job-level permissions: blocks. Only test-workload-identity has a job-level permissions block. Without explicit permissions, these jobs inherit the default repository permissions.

Locations:

- `.github/workflows/e2e-tests.yml:1`

## Iteration Notes

### Iteration 1

**Fixes applied:** unpinned-uses, missing-permissions, script-injection

**Notes:**

Fixed all 7 findings across 3 workflow files. (1) check-fallback-versions.yml: Added top-level permissions: {} and job-level permissions: contents: read; pinned actions/checkout@v6 and actions/setup-node@v6 to full commit SHAs. (2) test-e2e.yml: Added top-level permissions: {} and job-level permissions: contents: read to check-external-pr job; moved all github.* context expressions out of run: blocks into env: variables; applied tr -d newline sanitization when writing SHA values to GITHUB_OUTPUT. (3) e2e-tests.yml: Added top-level permissions: {} and job-level permissions: contents: read to 6 jobs; pinned all 10 occurrences of actions/checkout@v6 and actions/setup-node@v6 to full commit SHAs; fixed script injection in test-install (matrix.version), test-docker-hub-fallback (matrix.versionPath, matrix.channel, steps.expected.outputs.version), and test-baked-in-fallback (matrix.fallbackKey via process.env in Node.js, matrix.channel, steps.expected.outputs.version).

