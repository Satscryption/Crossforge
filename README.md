# Crossforge

**Claude architects. Independent models build. Evidence decides.**

Crossforge is a planned Claude Code plugin for orchestrating Claude, OpenAI
Codex, and xAI Grok across software-planning, implementation, verification,
review, and shipping workflows.

> [!IMPORTANT]
> This repository currently contains the approved Crossforge `0.1.0` build
> specification. The installable plugin has not been implemented yet.

Read the [full build specification](./CROSSFORGE_BUILD_SPEC.md).

## What Crossforge will do

Crossforge separates architectural judgment from implementation and mechanical
enforcement:

- Claude owns planning, context, and final candidate selection.
- Codex and Grok provide independent implementation and review lanes.
- A deterministic Python control layer manages worktrees, scope, state,
  provider invocation, verification, and evidence.
- Tests and repository evidence—not model agreement—decide whether a candidate
  is eligible.
- Publishing remains a separate, explicitly authorized operation.

Crossforge is not an LLM gateway and does not proxy, translate, or persist
provider credentials. It invokes locally authenticated provider CLIs.

## Architecture

```text
User
  -> Claude architect
      -> deterministic Crossforge control layer
          -> Codex candidate worktree
          -> Grok candidate worktree
          -> scope checks, sandboxed gates, and evidence
      -> selected and independently verified patch
      -> dedicated branch and task commit
  -> crossforge-ship
      -> final verification
      -> push and pull request
```

Each writing provider receives its own disposable Git worktree. Crossforge
captures a binary-safe patch, rejects out-of-scope changes, verifies the patch
in a fresh sandboxed worktree, and only then applies the exact verified content
to the orchestration branch.

## Core safety properties

| Property | Required behavior |
| --- | --- |
| Worktree isolation | One writer per worktree; competing candidates never share one |
| Exact scope | Every task has a non-empty file allowlist |
| Green before commit | Required gates pass against the exact candidate patch |
| Clean orchestration checkout | Candidate-controlled code never runs there |
| No silent fallback | Unavailable providers fail visibly and fallback is recorded |
| Credential ownership | Crossforge never reads, exports, or stores OAuth tokens |
| Context consent | Provider-visible source is scanned, hashed, and approved |
| Durable recovery | Run state survives interruption and context compaction |
| Safe shipping | Push and PR creation require the separate shipping skill |
| Idempotent publication | Retries discover existing remote state before writing |

The specification treats provider-readable repository content as transmitted
context. Denied paths are quarantined, readable text is secret-scanned, binary
context requires exact hash approval, and the resulting context manifest is
bound to provider consent.

## Planned modes

| Mode | Purpose |
| --- | --- |
| `plan` | Produce and approve one canonical implementation plan |
| `build` | Route tasks, generate candidates, verify, select, and commit |
| `review` | Perform read-only cross-vendor review |
| `resume` | Continue a consistent interrupted build |
| `status` | Inspect durable local state without calling providers |
| `crossforge-ship` | Revalidate and explicitly publish a completed run |

## Requirements

The planned MVP requires:

- Claude Code 2.1.216 or newer
- Python 3.11 or newer
- Git 2.39 or newer
- macOS, Linux, or WSL
- A supported local gate sandbox:
  - `sandbox-exec` on a compatible macOS system
  - `bwrap` on Linux or WSL

Optional provider integrations require locally installed and authenticated
CLIs:

```text
codex login
grok login
gh auth login
```

Codex and Grok versions will be capability-probed rather than pinned to a
specific release.

## Installation

Crossforge is not installable yet. Once the implementation and plugin manifests
described by the specification are present, the intended Claude Code
marketplace flow will be:

```text
/plugin marketplace add Satscryption/Crossforge
/plugin install crossforge@crossforge
```

Do not expect these commands to succeed against the specification-only
repository.

## Planned quick start

The canonical qualified skill names will be:

```text
/crossforge:crossforge
/crossforge:crossforge-ship
```

Example workflows:

```text
/crossforge:crossforge "Add optimistic locking to the account service" --mode plan

/crossforge:crossforge ./approved-plan.json --mode build --budget balanced

/crossforge:crossforge HEAD~1..HEAD --mode review

/crossforge:crossforge --mode resume

/crossforge:crossforge --mode status

/crossforge:crossforge-ship --run-id <run-id> --remote origin --target-branch main
```

Bare `/crossforge` and `/crossforge-ship` aliases may be available when they do
not collide with another installed skill, but documentation and automation
should use the qualified names.

## Routing and budget profiles

Crossforge will route tasks using risk, task class, provider availability,
project-local evidence, and the selected budget.

- `lean` minimizes unnecessary multi-model calls and disables automatic races.
- `balanced` uses independent review where risk justifies it.
- `quality` permits stronger planning and additional eligible candidate lanes.

The initial low-risk writer default is Codex. Grok is preferred for clearly
mechanical work such as fixtures, boilerplate, repetitive wiring, CRUD, and
straightforward UI assembly. Project-local provider statistics may adjust
routing only after a sufficient comparable sample.

## Provider consent and data flow

Crossforge will require repository- and provider-specific consent before a
remote model receives source-bearing context. Consent is bound to:

- Repository identity
- Provider and operation class
- Deny-path policy
- Managed policy
- Expiry
- The manifest of source files exposed for the operation

Consent must be renewed when any bound property changes. Secret findings report
only metadata such as path, line, detector, and severity; detected values are
never printed.

The trusted provider CLI retains access to its own authenticated session and
provider endpoint. Model-issued tools must remain confined to the disposable
candidate worktree and must not read provider credentials, the orchestration
checkout, repository-common Git data, or unrelated user files.

## State, worktrees, and recovery

Repository-scoped state will live under:

```text
<git-common-dir>/crossforge/
```

Candidate and verification worktrees will live beneath a validated temporary
root, normally:

```text
${CROSSFORGE_WORKTREE_ROOT:-${TMPDIR:-/tmp}/crossforge-worktrees}/
```

State includes the approved plan hash, task transitions, provider identity,
base commits, worktree records, context manifests, patches, gate evidence,
selection decisions, and shipment checkpoints.

Resume will stop rather than guess when the repository identity, branch, HEAD,
plan hash, sandbox policy, worktree evidence, or writer locks are inconsistent.
Crossforge will not use destructive recovery commands or automatically stash
user work.

## Shipping boundary

Normal Crossforge execution may create local branches and commits, but it may
not push or create a pull request.

Only `crossforge-ship`, invoked by a current explicit publication request, may:

1. Load a completed run.
2. Revalidate its branch, commit history, clean state, and approved plan.
3. Run the final structured gate in a fresh sandbox.
4. Record an immutable shipment authorization.
5. Push without force.
6. Discover or create exactly one matching pull request.
7. Persist remote readback so interrupted retries do not duplicate operations.

## Planned configuration

Configuration precedence will be:

1. Explicit invocation arguments
2. `.claude/crossforge.json`
3. `~/.claude/crossforge.json`
4. Safe defaults

Example:

```json
{
  "schemaVersion": 1,
  "budget": "balanced",
  "strategy": "auto",
  "providers": {
    "codex": {
      "enabled": true,
      "model": "auto",
      "effort": "high",
      "timeoutSeconds": 600
    },
    "grok": {
      "enabled": true,
      "model": "auto",
      "effort": "high",
      "timeoutSeconds": 600
    }
  },
  "gates": {
    "timeoutSeconds": 900,
    "sandboxBackend": "auto",
    "network": "deny",
    "executableAllowlist": []
  }
}
```

Unknown keys and unsafe values will be rejected rather than ignored.

## Troubleshooting

Until implementation begins, this repository is documentation-only. An
unrecognized skill or failed plugin installation is expected.

Once implemented, common blockers will include:

- Missing or unauthenticated provider CLI
- Provider CLI without the required safe headless capabilities
- Missing or inconclusive sandbox backend
- Dirty orchestration checkout
- Expired or mismatched provider consent
- Denied path or secret-scan finding
- Changed plan hash
- Stale task base commit
- Failed verification gate
- Inconsistent durable run state

Crossforge is designed to report these as explicit blockers without silently
weakening safety controls.

## Project status

The `0.1.0` product and implementation contract are complete. Implementation is
organized into sixteen ordered tasks covering:

1. Plugin scaffold and manifests
2. Models, configuration, and canonical plans
3. Git and exact-scope primitives
4. Durable state and locking
5. Consent and secret screening
6. Provider adapters and preflight
7. Candidate worktree lifecycle
8. Sandboxed gates and evidence
9. Routing and provider statistics
10. Candidate acceptance and commits
11. Deterministic control CLI
12. Claude agents and protocol references
13. Main skill
14. Shipping skill
15. Documentation and threat model
16. Evaluations and release validation

See the [ordered implementation tasks](./CROSSFORGE_BUILD_SPEC.md#37-ordered-implementation-tasks)
for the contractual file scopes and completion criteria.

## Contributing

Contributions should preserve the product invariants and remain consistent with
the approved specification. If an implementation detail is unspecified, choose
the smallest safe design and record it in
`docs/IMPLEMENTATION_DECISIONS.md` once that file exists.

Security controls must not be weakened merely to make an integration test pass.
Automated tests should use fake provider executables; real paid-provider calls
belong only in explicitly enabled live smoke tests.

## License and provenance

Crossforge `0.1.0` is specified for release under the MIT License. The repository
does not yet include the implementation scaffold or its `LICENSE` file.

The design is an independent implementation informed in part by
[`fable-advisor`](https://github.com/DannyMac180/fable-advisor), Copyright
2026 Dan McAteer, used under the MIT License. Crossforge is not endorsed by
Anthropic, OpenAI, or xAI.
