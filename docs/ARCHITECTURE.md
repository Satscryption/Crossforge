# Crossforge architecture

Crossforge separates product judgment from mechanical enforcement. Claude
plans, classifies risk, interprets evidence, and selects an eligible candidate.
The Python control layer validates every durable transition and safety
invariant. Codex and Grok are untrusted candidate authors whose reports do not
establish correctness.

## System view

```text
User
  -> Claude architect
      -> deterministic Crossforge control layer
          -> Codex candidate worktree
          -> Grok candidate worktree
          -> scope/gates/evidence
      -> selected patch
      -> accepted branch/task commit
  -> crossforge-ship
      -> push/PR
```

The normal skill and shipping skill are deliberately separate authorization
surfaces. The normal skill may create local branches and commits but cannot
publish them. The shipping skill requires a current explicit publication
request, a completed build, and remote readback.

## Judgment and enforcement

| Concern | Owner |
| --- | --- |
| User intent, architecture, assumptions, risk classification | Claude architect |
| Canonical schema, approval hash, transitions, locks | Control layer |
| Candidate source changes | Codex or Grok in one isolated lane |
| Provider summary and self-reported checks | Provider claim |
| Scope, executable identity, sandboxed gates, patch/tree hashes | Independent control-layer evidence |
| Comparison among eligible candidates | Claude architect |
| Local patch application and commit | Control layer |
| External publication authorization | User through `crossforge-ship` |

Claude cannot waive a failed invariant. A provider cannot make its work
eligible by claiming success. Deterministic code does not infer product
meaning, broaden a file allowlist, expand consent, or silently change provider
strategy.

## Components

The runtime package lives in
`skills/crossforge/scripts/crossforge_lib/` and uses only the Python standard
library.

| Module | Responsibility |
| --- | --- |
| `config.py`, `models.py`, `plan.py` | Strict configuration and canonical plan models, validation, rendering, approval hashes, and task materialization |
| `git.py`, `scope.py` | Repository discovery and identity, dedicated branches, exact changed-path calculation, mode/symlink checks, and filter-free staging |
| `state.py`, `locking.py` | Owner-private repository-common state, valid transitions, atomic pointers, and repository/run/writer locks |
| `consent.py`, `secrets.py` | Expiring policy-bound provider consent, deny-path quarantine, complete readable-context manifests, binary controls, and secret screening |
| `preflight.py`, `providers/` | Runtime discovery, version and authentication checks, capability evidence, safe Codex/Grok argv, bounded process execution, and sanitized errors |
| `worktrees.py` | Recorded detached worktrees, sanitized one-commit Git projections, patch capture, restoration, and proof-driven cleanup |
| `gates.py`, `evidence.py`, `reports.py` | Gate-command policy, executable identity, sandbox construction/probes, owner-only evidence, provider report validation, and independent eligibility |
| `routing.py` | Risk/budget/provider routing and comparable provider statistics |
| `acceptance.py` | Fresh-worktree patch verification, byte-identical application, filter-free staging, and task commit protocol |
| `shipping.py` | Completed-run validation and idempotent publication checkpoints |
| `crossforge.py` | Argument-array control CLI and stable operational exit codes |

The Markdown agents under `agents/` are read-only advisors. They are not
provider lane supervisors and cannot invoke Bash. Detailed skill protocols live
under `skills/crossforge/references/`.

## Plan and run lifecycle

`plan.json` is canonical. Claude produces its semantics; deterministic code:

1. rejects unknown keys and invalid field values;
2. validates exact file paths, task IDs, dependencies, and cycles;
3. validates every verification command as an argument array;
4. renders `plan.md` deterministically;
5. hashes the canonical JSON and checks explicit approval of that hash;
6. materializes `tasks.json` by adding runtime fields without semantic
   inference.

Any canonical plan change invalidates approval. A build requires a non-empty
global gate, and `--no-commit` requires exactly one task.

Build mode creates or reuses a safe dedicated branch, persists a run under the
repository-common Git directory, and executes tasks serially. Run transitions
are:

```text
active -> blocked | complete | abandoned
blocked -> active | abandoned
complete -> shipped
```

Task transitions are:

```text
pending -> in_progress | blocked
in_progress -> candidate_ready | blocked
candidate_ready -> accepted | blocked
accepted -> committed | complete | blocked
committed -> complete | blocked
blocked -> in_progress
```

State transitions are atomic and idempotent only when the complete existing
target record already matches.

## Exact provider data flow

### 1. Local preflight

Crossforge validates Python, Git, Claude Code when required, an
absolute-component-only `PATH`, and a platform-appropriate sandbox executable.
Executable version/help/login-status checks that make no model request may run
without source consent. Remote readiness calls do not.

### 2. Consent and capability

The repository identity is the SHA-256 of the canonical repository root and a
normalized, credential-free origin URL (or `<no-origin>`). A fixed,
source-free readiness prompt requires `probe` consent. Source-bearing
operations require consent for their exact provider and operation class.

Consent is also bound to expiry, the deny-policy hash, and the discovered
managed-policy hash. Provider capability evidence must prove denial of network,
outside-worktree access, common Git state, orchestration checkout, and
credential directories. Failed or inconclusive proof marks the provider
unavailable.

### 3. Candidate creation and context preparation

Crossforge creates a detached worktree at the task’s exact base commit and
registers it in `worktrees.json`. One writer holds an exclusive lock containing
only PID, hostname, provider, worktree, and start time.

Before a provider starts, the control layer:

1. enumerates tracked and non-ignored untracked provider-readable paths;
2. moves denied tracked paths to owner-only quarantine and omits denied
   untracked paths;
3. rejects escaping symlinks and unsafe file types;
4. quarantines binary files unless the plan approves the exact path and
   SHA-256;
5. scans readable text, reporting finding metadata but never values;
6. writes `context-manifest.json` with every readable path, type, size, and
   SHA-256;
7. creates a self-contained task brief from approved plan data and the
   interface ledger.

All readable repository- or user-controlled files count as transmitted
context, not just files quoted in the prompt.

### 4. Git-history isolation

A linked worktree’s `.git` control file would expose the common object
database and historical denied blobs. Crossforge moves that control file to
restricted evidence and creates an isolated repository with one baseline
commit containing only manifest-listed files.

The projection has no remotes, hooks, credential helpers, signing, executable
filters, automatic maintenance, or inherited Git configuration. It uses a
private temporary home and fixed identity
`Crossforge <crossforge@invalid>`. Its tree/commit IDs and effective sanitized
configuration are recorded in `runtime-manifest.json`.

### 5. Provider invocation

The trusted parent process sends the task brief:

- Codex uses `exec`, `workspace-write`, no approval prompts, ephemeral mode,
  strict config, and stdin bytes.
- Grok uses a compatible headless `dontAsk` mode, explicit tool allows,
  explicit network-capable tool denials, and an enforceable sandbox.
- Review lanes use read-only sandbox/tool permissions.

All subprocesses use argument arrays and new process groups. Timeouts terminate
descendants. Trusted stdout/stderr capture is written to owner-only evidence;
only sanitized bounded messages reach the user.

`crossforge.py invoke --request <json>` accepts one transaction document. The
top level is bound to the active run and task:

```json
{
  "schemaVersion": 1,
  "repository": "/absolute/repository",
  "gitCommonDir": "/absolute/repository/.git",
  "worktreeRoot": "/absolute/crossforge-worktrees",
  "registry": "/absolute/.git/crossforge/runs/<run-id>/worktrees.json",
  "runId": "<run-id>",
  "taskId": "T1",
  "operation": "implement",
  "denyPolicySha256": "<sha256>",
  "managedPolicySha256": "<sha256>",
  "lanes": [
    {
      "provider": "codex",
      "candidatePath": "/absolute/candidate",
      "capabilityEvidence": "/absolute/capability.json",
      "requestedModel": "auto",
      "effort": "high",
      "timeoutSeconds": 600
    }
  ]
}
```

Optional top-level fields are `configPath` and `allowFile`; an optional lane
field is `executable`. The schema rejects unknown fields. `lanes` contains one
lane normally or two distinct-provider lanes for a race. The trusted parent
prevalidates both lanes, runs a race concurrently in separate registered
worktrees, and waits for both process trees and restoration paths before
returning. Each actual call is atomically charged to the task before its
provider process starts; crash and timeout retries are therefore never free.
The control layer renders `spec.md` itself from the approved plan, durable task,
and interface ledger, then secret-scans the exact bytes; callers cannot supply
prompt text. Provider readiness additionally requires `probe` consent.

Capability evidence must be fresh (no older than 24 hours), executable- and
policy-bound, stored beneath the run's owner-private `evidence/preflight`
directory, and hash-bound in `run.json.providers`. An arbitrary path supplied
only by the invocation request is rejected. `record-capability` is the sole
transaction that validates and atomically copies trusted platform/provider
negative-probe output into that location and updates the run binding; if no
such platform probe is available, the provider remains unavailable. Every provider attempt writes to
an immutable `provider/attempt-NN/` directory containing its own brief,
context, runtime, policy, raw output, patch, and validated report.

### 6. Restoration, scope, and capture

After every provider descendant exits, Crossforge records isolated Git
metadata changes, removes only the contained isolated `.git`, restores the
original control file and quarantined files byte-for-byte, and calculates
scope against the task base. A provider-created denied-path collision is
restricted evidence and makes the candidate ineligible.

For an eligible-scope worktree, Crossforge captures a binary Git patch, hashes
it, proves it applies to a clean base, and confirms index cleanup does not
change the patch. Providers do not commit.

### 7. Independent verification

Candidate code never executes in the orchestration checkout. Gates use a fresh
verification worktree containing the exact base plus patch. The gate sandbox:

- binds only the verification worktree read/write;
- exposes required tools/system directories read-only;
- supplies a private `HOME`, temporary directory, and caches;
- denies network, provider credentials, common Git state, the orchestration
  checkout, and unrelated user files;
- starts a process group for descendant-safe timeouts.

The exact executable resolved through the approved `PATH` is recorded and
hashed. A changed executable requires reapproval. Gate output is preserved
locally with hashes; provider-reported verification cannot replace it.

### 8. Selection and acceptance

Hard-gate failures remove a candidate before comparison. Claude compares only
eligible candidates using requirement completeness, correctness, test quality,
security, interface fidelity, conventions, maintainability, complexity,
performance, and diff economy.

Acceptance repeats patch application, exact scope, and gates in a fresh
worktree. The control layer then applies the verified patch to a clean
orchestration branch and requires its scoped-tree hash to match the verified
tree byte-for-byte. It stages exact bytes without clean filters, disables
hooks/signing for the generated commit, and records the interface ledger.

## Routing and model independence

An explicit `codex`, `grok`, or `race` strategy is honored only when its
providers are enabled, available, consented, and policy-compatible. `auto`
uses task risk/class, budget, and comparable repository-local history. Fixed
strategies never fall back silently.

High-risk planning uses the read-only commitment advisor and independent plan
critiques where available. Claude-family review counts as independent only
when a known different provider family authored the candidate. Unknown
authorship is recorded rather than presented as independent.

## Durable state and locks

State lives at:

```text
<absolute-git-common-dir>/crossforge/
```

Directories are created owner-only and canonical files use same-directory
temporary files, flush, file `fsync`, `os.replace`, and directory `fsync` where
supported. `active` names at most one unfinished build; `latest-complete`
points to the newest unshipped completed build.

Lock order is fixed:

```text
repository.lock -> run.lock -> writer.lock
```

A live lock blocks. A same-host stale lock can be cleared only after proving
its PID is absent; a foreign-host stale lock needs explicit user approval.

## Recovery and cleanup

Resume treats disk state as authority and validates identity, branch, commits,
plan approval, tasks, locks, worktrees, evidence, scope, sandbox, and provider
capabilities before continuing. It never reconstructs state from conversation
memory.

Cleanup operates only on a canonical path recorded under the configured
worktree root. Dirty captured candidates require successful exact reverse-patch
proof and a clean result before ordinary `git worktree remove`. Crossforge
never force-removes or recursively deletes a candidate; uncertain cleanup
retains it.

## Shipping boundary

`crossforge-ship` loads a completed run, checks branch/history/cleanliness,
re-runs the global gate in a clean sandbox, and binds authorization to
repository identity, run, remote, head, target, and final commit.

It performs remote readback before each write, never force-pushes, durably
records a confirmed remote commit before PR work, and creates no PR when an
exact matching one already exists. A retry resumes from the last shipment
checkpoint. Dry-run performs no authorization or write.

## Security analysis

Security assumptions, threats, controls, and residual risks are maintained in
[THREAT_MODEL.md](THREAT_MODEL.md). Operational recovery is detailed in the
skill’s [recovery reference](../skills/crossforge/references/recovery.md).
