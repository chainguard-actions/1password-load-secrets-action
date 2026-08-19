<!-- markdownlint-disable -->

# Hardening Report: 1Password--load-secrets-action/v5.0.1

> This file was generated automatically by the hardening agent.

**Policy SHA:** `d636be7e43ef829af6e853da6b3c7566db9f72fe`

**Test Policy SHA:** `843adf9e4b8f85d0c08b27b9d0b09dd094b54702`

**Harden Agent Version:** `2`

Action **1Password--load-secrets-action/v5.0.1** was hardened automatically. 6 finding(s) were identified and resolved across 1 iteration(s).

## Findings Fixed

### script-injection (severity: high)

Sub-rule (a): The 'check-external-pr' job's run: block in test-e2e.yml directly interpolates multiple github.* context values inside shell commands without routing through env vars. Offending lines include: `echo "Event name: ${{ github.event_name }}"`, `if [ "${{ github.event_name }}" == "pull_request" ]`, `echo "PR head repo: ${{ github.event.pull_request.head.repo.full_name }}"`, `if [ "${{ github.actor }}" == "dependabot[bot]" ]`, `elif [ "${{ github.event.pull_request.head.repo.full_name }}" != "${{ github.repository }}" ]`, `echo "ref=${{ github.event.pull_request.head.sha }}" >> $GITHUB_OUTPUT`, `SHA_PARAM="${{ github.event.client_payload.slash_command.args.named.sha }}"`, `PR_HEAD_SHA="${{ github.event.client_payload.pull_request.head.sha }}"`, `echo "ref=${{ github.sha }}" >> $GITHUB_OUTPUT`. Any of these values could contain shell metacharacters injected by an attacker via a pull_request or repository_dispatch event.

Locations:

- `.github/workflows/test-e2e.yml:34`

### script-injection (severity: high)

Sub-rule (a): Multiple run: blocks in e2e-tests.yml directly interpolate ${{ matrix.* }} and ${{ steps.*.outputs.* }} expressions inside shell commands. Offending examples: `expected="${{ matrix.version }}"` (test-install job); `jq -r '${{ matrix.versionPath }}'` and `echo "Expected ${{ matrix.channel }} version: $version"` (test-docker-hub-fallback job); `src.match(/ReleaseChannel\.${{ matrix.fallbackKey }}\].../)` and `console.error('Could not find baked-in version for ${{ matrix.fallbackKey }}')` (test-baked-in-fallback job); `expected="${{ steps.expected.outputs.version }}"` (both fallback assertion steps). Matrix values and step outputs are workflow-controllable and must not be interpolated directly into shell.

Locations:

- `.github/workflows/e2e-tests.yml:313`
- `.github/workflows/e2e-tests.yml:355`
- `.github/workflows/e2e-tests.yml:356`
- `.github/workflows/e2e-tests.yml:407`
- `.github/workflows/e2e-tests.yml:408`
- `.github/workflows/e2e-tests.yml:409`
- `.github/workflows/e2e-tests.yml:432`
- `.github/workflows/e2e-tests.yml:461`

### github-env-injection (severity: high)

The 'check-external-pr' job's run: block in test-e2e.yml writes github context values directly to $GITHUB_OUTPUT without sanitization (no `printf '%s' ... | tr -d '\n\r'` step). Specifically: `echo "ref=${{ github.event.pull_request.head.sha }}" >> $GITHUB_OUTPUT` writes an attacker-influenced SHA directly; `echo "ref=$PR_HEAD_SHA" >> $GITHUB_OUTPUT` where PR_HEAD_SHA is set from `${{ github.event.client_payload.pull_request.head.sha }}`; and `echo "ref=${{ github.sha }}" >> $GITHUB_OUTPUT`. These writes allow newline injection into GITHUB_OUTPUT.

Locations:

- `.github/workflows/test-e2e.yml:47`
- `.github/workflows/test-e2e.yml:62`
- `.github/workflows/test-e2e.yml:72`

### missing-permissions (severity: medium)

e2e-tests.yml has no top-level permissions: block, and the following jobs also have no job-level permissions: block: test-service-account, test-service-account-smoke, test-connect, test-install, test-docker-hub-fallback, test-baked-in-fallback. Only the test-workload-identity job defines job-level permissions. This means those jobs run with the default (potentially broad) token permissions.

Locations:

- `.github/workflows/e2e-tests.yml:1`

### missing-permissions (severity: medium)

test-e2e.yml has no top-level permissions: block, and the check-external-pr and e2e jobs have no job-level permissions: block. Only the comment-pr job defines job-level permissions. This means check-external-pr and e2e run with default (potentially broad) token permissions.

Locations:

- `.github/workflows/test-e2e.yml:1`

### unpinned-uses (severity: high)

The test-workload-identity job in e2e-tests.yml uses tag-based (non-SHA) refs for two actions: `uses: actions/checkout@v6` and `uses: actions/setup-node@v6`. These are mutable tag references that can be silently updated to point to different (potentially malicious) commits. They should be pinned to full 40-character commit SHAs.

Locations:

- `.github/workflows/e2e-tests.yml:476`
- `.github/workflows/e2e-tests.yml:482`

## Iteration Notes

### Iteration 1

**Fixes applied:** script-injection, github-env-injection, missing-permissions, unpinned-uses

**Notes:**

Fixed all 6 findings across two workflow files:

1. test-e2e.yml script-injection: Moved all github.* context values (event_name, repository, actor, PR head repo/SHA, dispatch payload SHA, push SHA, ref_name) into the step's env: block. Shell script now references plain env vars.

2. e2e-tests.yml script-injection: Moved matrix.version, matrix.versionPath, matrix.channel, matrix.fallbackKey, and steps.expected.outputs.version into env: blocks. The node.js script in test-baked-in-fallback now reads FALLBACK_KEY via process.env instead of interpolation. The jq filter uses "$VERSION_PATH" env var instead of interpolated expression.

3. test-e2e.yml github-env-injection: All three GITHUB_OUTPUT writes that used github context values now sanitize with `printf '%s' "$VAR" | tr -d '\n\r'` before writing.

4. e2e-tests.yml missing-permissions: Added `permissions: {}` at top level; added `permissions: contents: read` to test-service-account, test-service-account-smoke, test-connect, test-install, test-docker-hub-fallback, and test-baked-in-fallback jobs.

5. test-e2e.yml missing-permissions: Added `permissions: {}` at top level; added `permissions: contents: read` to check-external-pr and e2e jobs.

6. e2e-tests.yml unpinned-uses: Pinned actions/checkout@v6 to SHA d23441a48e516b6c34aea4fa41551a30e30af803 and actions/setup-node@v6 to SHA 249970729cb0ef3589644e2896645e5dc5ba9c38 in test-workload-identity job.

