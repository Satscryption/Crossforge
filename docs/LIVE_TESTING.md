# Live testing

Crossforge’s default test suite never uses real provider credentials, makes a
model request, or pushes. Fake Codex, Grok, sandbox, and forge executables cover
automated integration behavior.

Live checks are optional and quota-consuming. This release provides the manual
procedure below rather than a bundled credential-consuming live-test runner.
Operators may set this marker while following the procedure:

```text
CROSSFORGE_LIVE_TESTS=1
```

No Crossforge 0.1.0 test or control command reads this variable, so it is not a
technical gate and grants no authority. Provider consent through
`/crossforge:crossforge-consent` and publication through
`/crossforge:crossforge-ship` remain separate user-invoked surfaces.
Consent additionally forces a user confirmation over a sealed disclosure.
Shipping's Python publication/destination flags remain caller-attested even
though the shipping skill itself requires direct user invocation. Never set
this variable in ordinary CI.

## Before testing

Confirm:

- the checkout contains no valuable uncommitted work;
- Python is 3.11+, Git is 2.39+, and Claude Code is 2.1.216+;
- `PATH` contains only absolute, non-empty components;
- `sandbox-exec` (macOS) or `bwrap` (Linux/WSL) is installed;
- the provider CLI under test is already authenticated;
- the test account has a bounded quota and no broad organization privileges;
- no provider or forge credential is copied into the repository or test
  environment;
- the test will run in a newly created disposable repository with no sensitive
  origin URL.

Authentication is provider-owned:

```text
codex login
codex login status
grok login
grok models
```

Crossforge must not inspect token files or print environment dumps.

## Required sequence

### 1. Run the offline suite

From the plugin root:

```text
python3 -m unittest discover -s tests -v
```

Do not continue after an offline failure.

### 2. Create a disposable repository

Use a private temporary directory, initialize Git, configure a test-only local
identity, and commit a minimal harmless file. Do not copy a real repository,
Git history, remote, environment file, credential, key, proprietary fixture,
or user document into it.

Example harmless content:

```text
def add(left, right):
    return left + right
```

The initial live task should change only a corresponding local test file.

### 3. Prove the gate sandbox first

Run Crossforge’s sandbox preflight before any provider request. The result must
prove:

- read/write access inside the disposable verification worktree;
- network denial;
- denial of writes outside the worktree;
- denial of repository-common Git state;
- denial of provider credential directories;
- denial of an unrelated random sentinel.

A failed or inconclusive negative test is a failure. Do not “temporarily”
relax the profile.

### 4. Initialize a one-task build locally

Create and approve the canonical one-task plan, then let the build workflow
initialize its active run before provider capability work. Confirm that no
Codex/Grok model request occurred during plan mode or before provider consent.
`record-capability` is run-bound and must reject a missing, completed, or
otherwise non-active run.

### 5. Approve probe consent, capability, and readiness

Approve only the `probe` operation class for the disposable repository. The
normal skill must first produce a sealed request and stop for direct invocation
of `/crossforge:crossforge-consent`. Confirm that the forced host prompt shows
the exact non-sensitive disclosure and that a declined or mutated request
writes no consent.

After consent, run `record-capability` for the active run. Verify that the
result is stored beneath that run's owner-private preflight evidence and is
derived from observed positive/negative effects, not caller-authored
booleans. Codex must use the fixed direct sandbox helper. Grok must have the
matching owner-private control-host receipt. Missing, forged, partial, stale,
or mutated helper/specification/hook evidence must fail closed.

Only after capability evidence is bound may the source-free readiness request
run. It must send a fixed prompt requesting `READY` (or the active model
identifier when checking an explicit model) and contain no repository path,
remote URL, file name, source, Git metadata, or prior output.

Record that this request may consume provider quota. Verify the resulting
probe evidence includes:

- executable path and CLI version;
- authentication result without credential values;
- requested model and resolved model or `cli-default`;
- the bound safe capability-evidence digest;
- a sanitized failure category when unavailable.

Run Codex and Grok separately. Do not interpret one provider’s result as proof
for the other.

### 6. Run one minimal source-bearing task

Review the exact `context-manifest.json` file count and byte total, then approve
only the required provider and `implement` operation for the disposable
repository. Use a one-task plan, an exact two-file allowlist, and a local
deterministic unit-test gate.

Verify:

1. the candidate worktree is detached at the recorded base;
2. denied paths and unapproved binary files are absent;
3. the provider sees a one-commit isolated repository with no remotes;
4. model-issued tools cannot use the network or read protected sentinels;
5. provider raw output is owner-only local evidence;
6. the original worktree Git control file and quarantine are restored;
7. exact scope and the independent gate pass;
8. candidate code executes only in a disposable verification worktree;
9. nothing is pushed and no PR is created.

For a race smoke test, use separate Codex and Grok worktrees and confirm each
has a distinct writer lock and evidence directory.

### 7. Exercise failure paths

Using disposable data only, confirm:

- missing consent blocks a remote probe;
- the normal skill can prepare but cannot record consent;
- a declined, expired, moved, or byte-mutated consent request writes nothing;
- expired or policy-mismatched consent blocks source transmission;
- an out-of-scope edit makes the candidate ineligible;
- a failed test blocks acceptance;
- an attempted network access fails inside the gate;
- timeout termination covers child processes;
- a changed base blocks application;
- uncertain cleanup retains the worktree.

Do not ask a real model to seek secrets or attack the host. Use fixed benign
sentinels created inside the disposable test hierarchy.

### 8. Shipping dry-run only

For routine live validation, use `crossforge-ship --dry-run`. It may perform
remote read-only preflight but must create no shipment authorization, push, or
PR.

Testing a real push requires a separate explicit decision, a disposable remote
owned for testing, and manual confirmation that no valuable repository is in
scope. It is not part of the standard live smoke procedure.

## Capturing results

Record:

- date, platform, and architecture;
- Python, Git, Claude Code, sandbox, and provider CLI versions;
- provider and requested/resolved model without account identifiers;
- exact Crossforge commit;
- which positive and negative probes passed;
- elapsed time and whether quota was consumed;
- sanitized failure categories;
- confirmation that no push occurred.

Do not record:

- OAuth tokens, cookies, credential paths, or full environment values;
- raw source, prompts, model output, or secret-detector values;
- personal temporary paths or remote URLs with user information.

Retain raw Crossforge evidence only in its owner-private Git-common state. A
public test report should contain hashes and non-sensitive summaries.

## Cleanup

Use Crossforge’s normal proof-driven cleanup. Never use a force-removal option
through Crossforge. If patch reversal, containment, cleanliness, restoration,
or lock proof fails, retain the worktree and evidence for inspection.

After a successful test, remove the disposable repository and remote through
the user’s normal administrative process. Revoking provider consent does not
log out or revoke the provider CLI session; manage that session with the
provider’s own CLI.

## Current release evidence

The 0.1.0 repository is delivered with offline fake-provider coverage. A real
Codex/Grok live call is intentionally not part of the normal build or unit-test
run. Record live results separately before promoting this alpha for sensitive
production use.
