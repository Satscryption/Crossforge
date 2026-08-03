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
          -> sealed provider-consent request
  -> crossforge-consent
      -> explicit user approval
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

The normal, user-invoked consent, and user-invoked shipping skills use
disjoint CLI surfaces. Skill-scoped host hooks allow each skill to call only
its own deterministic entry point. The normal skill may prepare consent
requests and create local branches and commits, but cannot record consent or
reach the supported publication surface. The consent skill is not
model-invocable, allows only its canonical Bash transaction, and forces an
exact disclosure prompt. Normal-skill file-mutation and subagent tools are
blocked so durable consent cannot be hand-written around the CLI. The shipping
skill requires a fresh caller-attested publication-intent flag, an unexpired
authorization, a completed build, a fresh final gate, a URL-bound remote, and
remote readback.

The normal hook's strict surface is bounded by an owner-private lease keyed by
hashes of the host session and prompt IDs. `activate-boundary` establishes the
lease before orchestration. An active durable-run pointer keeps enforcement
strict even after the invoking prompt. Without that pointer, a different
prompt expires the lease before evaluating the requested tool, while direct
writes to durable Crossforge state and `consent.json` remain blocked. Explicit
release is idempotent and is refused while a durable run remains active.

## Judgment and enforcement

| Concern | Owner |
| --- | --- |
| User intent, architecture, assumptions, risk classification | Claude architect; semantic judgment |
| Plan content and `planApproval` provenance | Claude/caller attestation; hash consistency only |
| Provider source-transmission consent | User-confirmed host prompt plus control-layer revalidation |
| Publication intent and destination override | User-invoked shipping boundary plus caller-attested flags |
| Canonical schema, plan hash binding, transitions, locks | Control layer |
| Candidate source changes | Codex or Grok in one isolated lane |
| Provider summary and self-reported checks | Provider claim |
| Scope, executable identity, sandboxed gates, patch/tree hashes | Independent control-layer evidence |
| Comparison among eligible candidates | Claude architect |
| Local patch application and commit | Control layer |
| Publication tuple and remote effects | Control layer after the user-scoped entry and caller attestations |

Claude cannot waive a failed invariant. A provider cannot make its work
eligible by claiming success. Deterministic code does not infer product
meaning, broaden a file allowlist, expand consent, or silently change provider
strategy. It also does not authenticate the human provenance of a
schema-valid plan approval, publication flag, destination override, or
recovery decision. Those attestations rely on the documented host workflow.

## Components

The runtime package lives in
`skills/crossforge/scripts/crossforge_lib/` and uses only the Python standard
library.

| Module | Responsibility |
| --- | --- |
| `config.py`, `models.py`, `plan.py` | Trust-separated configuration, canonical plan models, validation, rendering, approval hashes, and task materialization |
| `git.py`, `scope.py` | Repository discovery and identity, dedicated branches, exact changed-path calculation, mode/symlink checks, and filter-free staging |
| `state.py`, `locking.py` | Owner-private repository-common state, valid transitions, atomic pointers, and repository/run/writer locks |
| `consent.py`, `secrets.py` | Byte-bound short-lived consent requests, expiring policy-bound provider consent, deny-path quarantine, complete readable-context manifests, binary controls, and secret screening |
| `preflight.py`, `provider_capability.py`, provider capability helpers, `providers/` | Runtime discovery, version and authentication checks, control-produced capability evidence, safe Codex/Grok argv, bounded process execution, and sanitized errors |
| `worktrees.py` | Recorded detached worktrees, sanitized one-commit Git projections, patch capture, restoration, and proof-driven cleanup |
| `gates.py`, `evidence.py`, `reports.py` | Gate-command policy, executable identity, sandbox construction/probes, owner-only evidence, provider report validation, and independent eligibility |
| `routing.py` | Risk/budget/provider routing and comparable provider statistics |
| `acceptance.py` | Fresh-worktree patch verification, byte-identical application, filter-free staging, and task commit protocol |
| `shipping.py` | Completed-run validation and idempotent publication checkpoints |
| `crossforge.py`, the consent/shipping launchers, `crossforge_boundary.py` | Shared argument-array handlers, three disjoint CLI surfaces, fail-closed skill boundaries, and stable operational exit codes |

The Markdown agents under `agents/` are read-only advisors. They are not
provider lane supervisors and cannot invoke Bash. Detailed skill protocols live
under `skills/crossforge/references/`.

User configuration and safe defaults establish the gate/context trust floor.
Repository-controlled project configuration keeps precedence for ordinary
settings but cannot add gate environment variables, remove deny paths, or
widen a non-empty executable restriction. Gate environment construction also
removes credential-shaped names after allowlist resolution.

## Plan and run lifecycle

`plan.json` is canonical. Claude produces its semantics; deterministic code:

1. rejects unknown keys and invalid field values;
2. validates exact file paths, task IDs, dependencies, and cycles;
3. validates every verification command as an argument array;
4. renders `plan.md` deterministically;
5. hashes the canonical JSON and checks that the caller-attested approval
   record names that hash; this proves byte binding, not human provenance;
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

Release 0.1.0 creates provider capability evidence only after `init-run`
establishes an active build, because the evidence path and its binding are
run-scoped. Plan mode, standalone review, and status perform no external
provider transaction.

The repository identity is the SHA-256 of the canonical repository root and a
normalized, credential-free origin URL (or `<no-origin>`). A fixed,
source-free readiness prompt requires `probe` consent. Source-bearing
operations require consent for their exact provider and operation class.
The schema-reserved `plan` operation is not prepared or invoked in 0.1.0.
External `review` operations belong only to active build tasks; standalone
review is local.

Consent is also bound to expiry, the deny-policy hash, the discovered
managed-policy hash, the exact provider executable path and content hash, and
for source-bearing operations the canonical context-manifest hash and counts.
The normal skill derives those facts and a context-manifest summary into an
owner-private request whose exact bytes are valid for at most 15 minutes. It
cannot approve the request. The separate `crossforge-consent` skill requires
direct user invocation, revalidates every live binding and the request hash,
and returns `permissionDecision: ask` from its `PreToolUse` hook with the exact
non-sensitive disclosure. Only the consent CLI can then write `consent.json`.
Invocation rechecks the manifest after acquiring the candidate writer lock.
Provider capability evidence must prove denial of network, outside-worktree
access, common Git state, orchestration checkout, and credential directories.
Failed or inconclusive proof marks the provider unavailable.

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
only sanitized bounded messages reach the user. Git failures expose a stable
category and return code without argv, working directories, executable paths,
or raw diagnostics.

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
producer and binding transaction: it resolves the installed provider from
`PATH`, requires it to match the identity explicitly pinned by
the user-only `record-consent` surface, rejects executable locations beneath
repository, state, or temporary roots, creates nonce-bound protected
sentinels, and requires repository-bound `probe` consent. Codex launches
Crossforge's fixed helper
directly through the CLI's stable sandbox command. Grok exposes only its
command tool and must produce a parent-private control-host hook receipt for
the exact sealed helper command. The trusted parent re-hashes the helper,
specification, hook, and hook settings after execution, then derives schema-v2
results from observed read, write, and loopback-network effects. Callers cannot
supply booleans, an evidence path, or an executable override. Missing, forged,
mutated, partial, failed, or inconclusive output is rejected and never bound.
Every provider attempt writes to an immutable
`provider/attempt-NN/` directory containing its own brief, context, runtime,
policy, raw output, patch, and validated report. The control layer hashes the
exact report bytes it validates and records both that digest and the canonical
report path on the candidate entry in the active run registry.

### 6. Restoration, scope, and capture

After every provider descendant exits, Crossforge records isolated Git
metadata changes, removes only the contained isolated `.git`, restores the
original control file and quarantined files byte-for-byte, and calculates
scope against the task base. `invoke` persists the resulting report before
returning exit 5 for a scope violation. A provider-created denied-path
collision is restricted evidence and makes the candidate ineligible. Deny
globs use platform-independent case-insensitive matching.

For an eligible-scope worktree, Crossforge captures a binary Git patch, hashes
it, proves it applies to a clean base, and confirms index cleanup does not
change the patch. Candidate creation, capture, selection, acceptance, and
cleanup all require the repository identity, current commit, task, and registry
to match the active durable run. External-provider capture additionally
revalidates the canonical invocation report and requires its patch hash to
equal the newly captured patch. Selection durably binds the candidate and
report paths plus report digest. It also replays that captured patch in a fresh
verification worktree, derives every gate from durable task policy, proves the
gates leave the patch/tree unchanged, and binds a receipt path and digest.
Acceptance rechecks both bindings. Providers do not commit.

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
performance, and diff economy. Selection parses only report bytes matching the
candidate's invocation digest and requires report provider, base, and patch
identity to match the recorded candidate. It never accepts caller-authored gate
results: the control layer runs the complete ordered gate suite against the
exact captured patch and records a receipt bound to the run, task policy,
candidate, patch, sandbox policy, replay-derived quarantine set, and exact gate
artifacts. Receipt reads reject symlinks, hard links, non-private ownership or
permissions, and descriptor swaps. Selection and acceptance bind their state
with repository-then-run compare-and-swap locking; acceptance finalizes its task
record before releasing the lock that protects patch application and commit.
Before orchestration changes, it persists an acceptance intent bound to the
candidate patch, verified tree, quarantine set, gate receipt, commit message,
and commit mode. A retry can therefore prove and bind an already-created
commit or exact staged no-commit result after interruption. Generic task
transitions cannot create `candidate_ready`, and selection CAS ignores only
non-policy routing/attempt bookkeeping.

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

High-risk planning uses the read-only commitment advisor and local Claude
critique. Release 0.1.0 does not call Codex or Grok for plan-mode critique or
standalone review. During build work, Claude-family candidate review counts as
independent only when a known different provider family authored the
candidate. Unknown authorship is recorded rather than presented as
independent.

## Durable state and locks

State lives at:

```text
<absolute-git-common-dir>/crossforge/
```

State-facing command boundaries discover the target repository and bind its
resolved common Git directory before reading or mutating this tree. An
explicit state path cannot redirect status, run/task transitions, capability
evidence, or completion into another repository's control directory.

Directories are created owner-only and canonical files use same-directory
temporary files, flush, file `fsync`, `os.replace`, and directory `fsync` where
supported. `active` names at most one unfinished build; `latest-complete`
points to the newest unshipped completed build.

Lock order is fixed:

```text
repository.lock -> run.lock -> writer.lock
```

A live lock blocks. A same-host stale lock can be cleared only after proving
its PID is absent; a foreign-host stale lock needs a caller-attested recovery
approval whose human provenance is not independently authenticated.

## Recovery and cleanup

Resume treats disk state as authority and validates identity, branch, commits,
plan approval, tasks, locks, worktrees, evidence, scope, sandbox, and provider
capabilities before continuing. It never reconstructs state from conversation
memory.

Multi-record run/task mutations, including the task-completion interface ledger
update, use a bound before/after journal while holding the repository lock
followed by the run lock. Recovery uses the same lock order and behaves as a
compare-and-swap: it completes only a recognized partial snapshot while the
active pointer still agrees, removes an already-completed journal
idempotently, and refuses to overwrite newer or terminal state.

Cleanup operates only on a canonical path recorded under the configured
worktree root. Dirty captured candidates require successful exact reverse-patch
proof and a clean result before ordinary `git worktree remove`. Crossforge
derives evidence durability from the captured registry state and exact patch
digest instead of accepting a caller flag. It never force-removes or
recursively deletes a candidate; uncertain cleanup retains it.

## Shipping boundary

`crossforge-ship` loads a completed run, checks branch/history/cleanliness,
re-runs the global gate in a clean sandbox, and binds authorization to
repository identity, run, remote, head, target, and final commit.

Direct invocation of the non-model-invocable shipping skill establishes the
supported user-scoped entry boundary. The Python
`--publication-requested` and `--target-change-approved` values remain
caller-attested; deterministic shipping proves the resulting authorization
tuple and remote effects, not the original prompt or identity of the caller
who supplied those flags.

It performs remote readback before each write, never force-pushes, durably
records a confirmed remote commit before PR work, and creates no PR when an
exact matching one already exists. A retry resumes from the last shipment
checkpoint. Shipment recording and the final run transition share the
repository→run lock scope, so a retry can finish either side of an interrupted
terminal checkpoint without racing another shipping mutator. Dry-run performs
no authorization or write.

## Security analysis

Security assumptions, threats, controls, and residual risks are maintained in
[THREAT_MODEL.md](THREAT_MODEL.md). Operational recovery is detailed in the
skill’s [recovery reference](../skills/crossforge/references/recovery.md).
The implementation status of security-review findings #3–#15 is indexed in
[SECURITY_REVIEW_CLOSEOUT.md](SECURITY_REVIEW_CLOSEOUT.md).
