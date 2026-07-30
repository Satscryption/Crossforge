# Implementation Decisions

This log records choices that the build specification leaves open. Contractual
requirements, invariants, and schemas are not weakened by these decisions.

## ID-001: Canonical plugin distribution and Python package layout

- **Status:** Accepted
- **Decision:** The repository root and its Claude marketplace manifest are the
  canonical Crossforge distribution. Setuptools discovery exposes only the
  importable `crossforge_lib` package from
  `skills/crossforge/scripts`; a Python wheel is not a Crossforge plugin
  distribution.
- **Reason:** Claude Code requires the manifests, skills, agents, references,
  control entry point, and documentation in their repository-relative layout.
  The Python package metadata remains useful for import and tooling checks but
  does not claim to bundle those plugin assets.
- **Consequences:** Install Crossforge from the repository/marketplace as
  documented in the README. A wheel contains only the control library, omits
  the Claude plugin and `crossforge.py` entry point, and is not a supported
  installation artifact. setuptools is a build-system requirement only;
  Crossforge has no Python runtime dependencies.

## ID-002: Scaffold tests

- **Status:** Accepted
- **Decision:** Use `unittest` plus Python 3.11's `tomllib` for bootstrap
  validation.
- **Reason:** This validates JSON manifests and Python project metadata without
  adding a test framework or making a network request.
- **Consequences:** Test discovery is run with
  `python3 -m unittest discover -s tests -v` from the `crossforge` directory, or
  with `-s crossforge/tests` from its parent.

## ID-003: Canonical JSON encoding

- **Status:** Accepted
- **Decision:** Serialize canonical state JSON as UTF-8 with sorted keys,
  two-space indentation, no ASCII escaping, and one trailing newline.
- **Reason:** The specification requires deterministic bytes but leaves their
  presentation open. A readable stable form supports inspection while still
  producing an exact approval and evidence hash.
- **Consequences:** Hash-bound approval applies to this normalized
  representation. Input object key order has no effect; a semantic field
  change does.

## ID-004: Immutable normalized models

- **Status:** Accepted
- **Decision:** Normalize configuration and plan data into frozen, slotted
  dataclasses, with arrays represented as tuples and contractual enums as
  string enums.
- **Reason:** Immutable normalized objects prevent a later orchestration step
  from silently changing approved semantics in memory.
- **Consequences:** JSON adapters explicitly convert models back to the
  contractual camel-case schema. Runtime state remains plain validated JSON
  where atomic mutation is required.

## ID-005: Evidence namespace separation

- **Status:** Accepted
- **Decision:** Store provider-originated claims beneath a
  `provider-claims/` namespace and independently generated control-layer
  evidence beneath `independent/` in the evidence abstraction.
- **Reason:** Provider reports and test claims must never be mistaken for
  independently reproduced facts.
- **Consequences:** Eligibility code must consume independent scope/gate
  results explicitly; a complete provider report alone cannot make a candidate
  eligible.

## ID-006: Fail-closed capability injection

- **Status:** Accepted
- **Decision:** Provider adapters require control-produced sandbox capability
  evidence to be supplied by preflight. An adapter with no capability source
  reports `sandbox_inconclusive` and is unavailable.
- **Reason:** A CLI’s presence, authentication, or help text does not prove its
  model-issued tools are contained under the installed version and managed
  policy.
- **Consequences:** Runtime evidence comes only from `record-capability`'s
  fixed negative-probe producer. Tests may inject deterministic observations;
  production has no permissive or caller-authored fallback.

## ID-007: Repository-root plugin layout

- **Status:** Accepted
- **Decision:** Treat the repository root containing `.claude-plugin/` as both
  the plugin root and marketplace root.
- **Reason:** The specification’s `crossforge/` tree names the repository
  artifact, not an additional install-time directory. Publishing that artifact
  at the repository root makes Claude Code discovery and marketplace-relative
  `source: "./"` resolution unambiguous.
- **Consequences:** Local installation adds `.` from the cloned repository (or
  its absolute root path) as the marketplace.

## Deviations

### DEV-001: Alpha provider transaction scope

The bundled 0.1.0 control transaction invokes Codex/Grok only for active build
tasks. Plan-mode critique and standalone review remain local, read-only Claude
workflows; they do not claim cross-vendor independence. This is an explicit
alpha limitation pending dedicated durable non-build transaction state.

### DEV-002: Provider capability probe integration

`record-capability` runs Crossforge's fixed, source-free negative-probe helper
through the installed provider's workspace sandbox and atomically binds only
the resulting producer-marked schema-v2 evidence. Codex uses its direct
`sandbox` command; Grok requires a control-host hook receipt for the exact
sealed helper command. The parent rechecks all contract bytes and observes a
positive workspace control plus denied network, outside-write, credential,
orchestration, Git-common, outside-sentinel, and final-output operations.
The user-only `record-consent` surface pins the resolved executable path and
hash. The capability command accepts no caller-authored evidence or executable
override. A missing
receipt or helper execution, contract mutation, malformed or partial result,
unsafe or changed executable identity, or failed check leaves the provider
unavailable. Repository-bound `probe` consent is checked before any external
provider request.

### DEV-003: User-controlled provider consent

Provider consent uses a split prepare/approve protocol. The normal Crossforge
surface exposes only `prepare-consent`, which derives repository identity,
effective deny policy, provider executable identity, expiry, and
the canonical context-manifest hash and counts into an owner-private request
with a 15-minute validity window and an exact byte hash. It cannot write
`consent.json`.

Approval is isolated in the `crossforge-consent` skill, which is marked
`disable-model-invocation: true` and has a disjoint launcher. Its
`PreToolUse` hook revalidates the request and all live derivable bindings, then
returns `permissionDecision: ask` with the exact `consent_summary()`
disclosure. The CLI revalidates the same byte hash after approval before
recording consent. This makes the user permission decision—not model text or a
caller boolean—the provenance of approval.

The durable consent entry preserves the approved context-manifest hash and
counts. Source-bearing invocation compares both the early candidate snapshot
and a writer-lock-held snapshot against that binding before the provider can
read source. A changed candidate therefore requires a fresh request and user
approval.

The managed-policy digest remains an input from managed-policy discovery and
is displayed and bound exactly; improving that discovery trust anchor belongs
to the managed-policy finding rather than this consent-boundary change.

### DEV-004: Repository configuration is tighten-only for trust policy

Project `.claude/crossforge.json` remains higher precedence for ordinary
workflow settings, but it is untrusted repository content for provider-context
and gate policy. The loader compares the normalized project result with the
merged user/default policy: environment and executable allowlists may only
narrow, while deny paths may only grow. An empty executable list represents
the plan-approved executable set, so a project may introduce a restriction
without gaining execution authority. Each gate intersects a configured list
with the executable basenames in its approved plan before constructing the
runner. Gate environment construction separately filters credential-shaped
names even when an upstream allowlist contains them.

### DEV-005: Candidate provenance is active-run and invocation bound

Candidate lifecycle commands derive state from the repository-common active
run and accept only its canonical `worktrees.json`. They recheck repository
identity, orchestration commit, active task, task base, and the derived
repository-ID prefix rather than trusting caller paths.

After a provider process exits and its report and referenced evidence validate,
`invoke` stores both the canonical run-evidence report path and the exact
report-byte SHA-256 on the matching candidate entry. External-provider capture
re-loads and re-hashes that report, then requires the captured patch hash to
match it. Selection persists the exact candidate path, report path, and report
digest on the durable task. Acceptance requires those values to remain equal
and revalidates the report, provider, base, and patch immediately before use.
Legacy registry entries remain readable with null evidence fields but cannot
pass the external-provider capture, selection, or acceptance boundary.

Cleanup is also permitted while the active run and task are blocked, so
exhausting provider attempts cannot strand a safely reversible candidate.

### DEV-006: Selection gates are control-run and patch-bound

`record-selection` does not accept `independentGateResults`, caller allowlists,
or caller symlink approvals. It derives policy from the active durable task,
applies the captured patch to a fresh verification worktree, runs every
verification command in durable order, and rejects failure, mutation, or
incomplete evidence.

After successful cleanup of that verification worktree, it writes a receipt
bound to repository identity, run, approved plan, task policy, candidate,
provider, base, patch, sandbox policy, scoped-tree hash, and complete gate
results. The task stores the receipt's canonical path and exact SHA-256.
Acceptance revalidates the receipt and referenced result, output, and sandbox
policy files before independently rerunning acceptance gates.

The state layer rejects generic transitions into `candidate_ready`; only the
selection compare-and-swap binder may create that status. Its stale-state check
freezes selection/security fields while permitting independently durable
routing, attempt counters, and timestamps to advance during the gate run.

Acceptance persists a versioned intent before changing orchestration. The
intent binds the patch, verified scoped tree, quarantine digest, selected gate
receipt, commit message, provider, base, and commit mode. Successful binding
retains the intent as audit/retry evidence. If a process stops after staging or
commit, the next identical request must revalidate repository, candidate, and
evidence state, then finish or idempotently bind the exact result.

## Verification limitations

- The default suite uses fake provider, sandbox, and forge executables.
- No credential-consuming Codex or Grok call was made while implementing
  0.1.0.
- No real push or pull request was made.

These are release-evidence limitations, not weakened runtime behavior. Follow
`LIVE_TESTING.md` before promoting the alpha for sensitive source.
