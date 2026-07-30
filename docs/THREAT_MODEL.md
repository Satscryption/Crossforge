# Crossforge threat model

## Scope and security objective

Crossforge coordinates remote coding models over a local Git repository. Its
security objective is to prevent source transmission outside its supported
user-confirmed consent surface, contain provider-authored changes,
independently verify candidates without exposing the user’s wider machine,
preserve recoverable local state, and make external publication a separate
user-invoked action.

The Python control layer, canonical plan bytes once accepted as policy, local
policy, Git executable, sandbox backend, and operating-system isolation are
trusted. Plan semantics and approval provenance are not independently verified.
Repository content, provider output, provider-authored code, test/build
scripts, worktree Git metadata after provider access, and remote forge state
are untrusted until validated.

## Assurance vocabulary and orchestrator boundary

Crossforge uses these terms precisely:

- **Control-verified** means the Python layer derives a result from observed
  bytes, process effects, repository state, or remote readback and does not
  accept an equivalent caller-authored result. Capability probes, exact scope,
  replayed gates, patch/tree hashes, selection receipts, and shipping readback
  are control-verified.
- **User-confirmed** means the supported host boundary forces a user prompt
  over a control-generated disclosure. Provider consent has this assurance:
  the non-model-invocable consent skill and its hook force an `ask` decision,
  then the control layer revalidates the sealed request.
- **Caller-attested** or **model-attested** means the control layer validates
  schema and internal consistency but cannot prove that the statement came
  from the user or is semantically true. Plan content and `planApproval`,
  publication-intent and destination-override flags, recovery decisions, and
  micro-fix semantic inputs are in this category.
- **Provider claim** is untrusted provider-authored narrative or reported
  status. It never substitutes for control-verified evidence.

The `crossforge-ship` skill is non-model-invocable, so direct user invocation
establishes a supported host-level publication boundary. The Python
`--publication-requested` and `--target-change-approved` flags are still
caller attestations; they prove neither the original prompt nor who supplied
the assertion. Likewise, plan approval is hash-bound but has no separate
user-only approval hook.

Honest framing: Crossforge strongly defends the user against provider and
repository misbehavior. It constrains a misaligned orchestrating model with
deterministic invariants after policy is recorded, but relies on workflow
convention for model-attested intent, plan semantics, and recovery assertions.

## Assets

- User source code, including files outside an individual task’s scope
- Secrets and sensitive files in or near the repository
- Provider OAuth sessions and credential directories
- Repository-common Git objects, refs, configuration, and history
- The orchestration checkout and uncommitted user work
- Accepted canonical plan meaning and exact file allowlists
- Provider task briefs, prompts, stdout/stderr, reports, and patches
- Gate executables and their identities
- Durable run, consent, lock, evidence, and shipment state
- Local branches and commits
- Remote branches and pull requests

## Trust boundaries

### User and Claude architect

The user supplies intent and Claude translates it into plans, selections, and
control-layer requests. The consent hook obtains a distinct user confirmation
for provider source transmission. Plan approval, recovery decisions, and
shipping intent/override flags remain model-attested within their documented
host workflows. Claude cannot waive a failed deterministic invariant, but a
schema-valid attestation does not prove that Claude represented the user’s
meaning faithfully.

### Deterministic control layer

The local Python package validates schemas, paths, policy hashes, state
transitions, locks, provider invocation arguments, scope, gate results, patch
identity, acceptance, and shipping checkpoints. Expected failures use stable
exit codes and sanitized messages.

### Provider host versus provider-issued tools

The authenticated Codex or Grok CLI host may communicate with its provider
endpoint using its own session. Model-issued tools are confined to the
candidate worktree, cannot use the network, and must not read provider
credentials, the orchestration checkout, common Git state, or unrelated user
files. Capability probes must prove this distinction.

### Candidate versus verification

Candidate code and repository scripts are untrusted. They execute only in a
fresh verification worktree inside a separate gate sandbox, never in the
orchestration checkout.

### Local versus remote publication

Normal Crossforge execution stops at local commits. `crossforge-ship` is a
separate user-invoked boundary with an immutable authorization tuple,
read-before-write behavior, and durable idempotency checkpoints. Its host
invocation is user-scoped; its Python intent and target-override flags are
caller-attested.

### Misaligned orchestrating model

**Threat:** The orchestrating model creates a schema-valid plan or approval,
asserts publication or recovery intent that the user did not grant, or
misrepresents semantic judgment while all byte-level bindings remain valid.

**Mitigations:**

- Provider consent uses a sealed, control-generated disclosure and a forced
  user confirmation outside the model-invocable skill.
- Normal build mode cannot access the shipping CLI, and the shipping skill
  requires direct user invocation.
- Once recorded, plan hashes, task policy, scope, gates, state transitions,
  acceptance, and shipping tuples are deterministic and cannot be waived by
  model text.
- Caller-attested fields are labeled as such and are not described as
  independently verified user decisions.

**Residual risk:** There is no separate user-only hook for plan approval,
publication-intent flags, destination overrides, foreign-host recovery
approval, or other recovery decisions. A misaligned orchestrator can fabricate
those attestations when it can reach the corresponding supported surface.
Operators must inspect them; Crossforge cannot authenticate their semantic
provenance.

## Data-flow threats and mitigations

### Prompt injection from repository content

**Threat:** Source, comments, fixtures, documentation, generated files, or test
output instruct a model to ignore the approved task or exfiltrate data.

**Mitigations:**

- A self-contained task brief states that repository content is untrusted data.
- The approved objective, constraints, allowlist, base, and verification
  commands are repeated explicitly.
- Model tools are sandboxed with no network and restricted filesystem access.
- Exact scope and independent gates determine eligibility, not the provider’s
  narrative.

**Residual risk:** A model can still generate subtly malicious in-scope code.
Independent gates and review reduce but do not eliminate semantic supply-chain
risk.

### Fabricated independent gate results

**Threat:** A caller labels an arbitrary object as a passing independent gate
and causes an unverified candidate to enter `candidate_ready`, misleading the
selection record even though acceptance would later rerun real gates.

**Mitigations:**

- `record-selection` rejects caller-supplied gate-result objects.
- The control layer derives the allowlist, symlink approvals, exact ordered
  commands, and sandbox policy from the active durable run/task.
- It applies the exact captured patch in a fresh verification worktree, runs
  every gate, and proves the gates did not change the patch or scoped tree.
- A receipt binds repository identity, run, plan, task policy, provider,
  candidate path, base, patch, gate policy, results, outputs, and sandbox
  policies. Quarantine paths are derived from the replayed tree and bound by
  digest. Selection stores the receipt's exact path and digest.
- Receipt artifacts are opened from a filesystem anchor without following any
  symlink component, then ownership, private mode, link count, and hashes are
  checked against bytes read from the same descriptors.
- Selection and acceptance use repository/run compare-and-swap transactions;
  acceptance writes task state before releasing the repository lock used for
  isolated verification, patch application, and commit.
- Only the selection binder may enter `candidate_ready`; task-state validation
  requires selected candidate and gate-receipt bindings for selected states.
- Before applying in orchestration, acceptance records a durable intent bound
  to the exact patch, verified tree, quarantine set, gate receipt, commit
  message, and no-commit policy. Retries prove and bind an interrupted exact
  commit or staged result instead of duplicating it or becoming stranded.
- Acceptance re-hashes and validates the receipt before its separate fresh
  verification pass.

### Secret or unintended source transmission

**Threat:** Prompt assembly or model-issued reads send credentials, denied
files, binary artifacts, or unrelated source to a provider.

**Mitigations:**

- Provider availability is never consent.
- Consent binds repository identity, provider, operation class, expiry,
  deny-policy hash, managed-policy hash, canonical provider executable, and
  source-manifest hash and counts.
- The normal model-invoked skill can only prepare a 15-minute, exact-byte-hash
  consent request. Its fail-closed hook permits only known tools, blocks writes
  to durable Crossforge state or any `consent.json`, and allows only the two
  bundled read-only agent types.
- Only a directly user-invoked, non-model-invocable consent skill can record
  the request. It permits only the canonical consent transaction; its host
  hook recomputes live bindings and forces a user permission prompt containing
  `consent_summary()` output.
- Every provider-readable regular file and symlink is manifested with path,
  type, size, and SHA-256.
- Source-bearing consent is rechecked against the candidate manifest while
  holding its writer lock, before any provider source access.
- Denied tracked files are quarantined; denied untracked files are omitted.
- Binary files require exact path/hash approval.
- Readable text is secret-scanned; findings expose metadata, never values.
- Oversized unscannable text blocks without an exact unexpired exception.
- Escaping symlinks and path components are rejected.

**Residual risk:** Pattern and entropy detectors cannot recognize every secret
or sensitivity category. Consent presents file count and byte volume, and the
user remains responsible for repository classification. An agent run outside
the installed Crossforge skill hooks shares the user's operating-system
identity and is outside this plugin-enforced approval boundary.

### Repository-controlled policy weakening

**Threat:** A checked-out `.claude/crossforge.json` removes deny paths, exposes
additional inherited environment variables, or widens the executables allowed
to run in an independent gate.

**Mitigations:**

- Safe defaults and user configuration establish the trusted policy floor.
- Project `denyPaths` must retain every trusted pattern and may only add more.
- Project gate environment allowlists may only remove trusted names.
- A project may narrow a non-empty user executable allowlist, never widen or
  remove it. When the trusted list is empty, a project list adds a restriction
  to the exact executables already approved in the plan. Gate construction
  enforces this by intersecting configured names with plan-approved basenames.
- Credential-shaped environment names are filtered after allowlist merging,
  including generic key suffixes, API/access keys, credential-store paths,
  database connection URLs, and Kubernetes configuration.

### Git-history disclosure

**Threat:** A linked worktree’s `.git` control file gives provider tools access
to common objects containing deleted, denied, or historical content.

**Mitigations:**

- The linked-worktree control file is quarantined outside provider access.
- The provider sees a one-commit isolated repository containing only
  context-manifest paths.
- The projection has no remote, inherited configuration, credential helper,
  hook, signing, maintenance, or executable filter.
- The original control file is restored byte-for-byte before scope checks.

### Provider modifying out-of-scope files

**Threat:** A provider edits, deletes, renames, changes modes, creates
submodules/special files, or alters a symlink outside the approved scope.

**Mitigations:**

- Every task has an exact non-glob repository-relative allowlist.
- Scope includes staged, unstaged, deleted, untracked, both rename sides, and
  mode-only changes.
- Gitlinks, unsafe modes, parent symlinks, and escaping targets are rejected.
- Scope runs after provider/correction calls, before capture, around
  verification, after orchestration application, and before staging.
- Candidate races use separate worktrees with one writer each.

### Dangerous provider commands

**Threat:** A provider runs arbitrary commands, modifies the host, reaches the
network, accesses credentials, or performs Git publication.

**Mitigations:**

- Provider adapters use fixed argument arrays and fail-closed permission modes.
- Unsafe blanket-approval flags and full-access sandboxes are forbidden.
- Model-tool network, outside-worktree, common-Git, orchestration, and
  credential access are negatively probed.
- Provider processes start new process groups and descendants are terminated on
  timeout.
- Providers do not commit, push, create PRs, or edit Git configuration.

**Residual risk:** Crossforge depends on the installed provider CLI and
operating-system sandbox correctly enforcing probed behavior. A compromised
trusted CLI host binary is outside the threat model.

### Malicious or malformed plan commands

**Threat:** A plan embeds shell interpolation, inline code, destructive
filesystem/Git operations, privilege changes, credential commands, or remote
writes in a verification gate.

**Mitigations:**

- Gate commands are non-empty argument arrays, never shell strings.
- Unknown fields, empty/control-character arguments, shell operators, inline
  interpreter flags, dangerous operations, and unsafe executables are rejected.
- The user sees exact executables and arguments before hash-bound plan
  approval.
- Executables resolve through a safe `PATH`; canonical identity is recorded and
  changes require reapproval.
- Checked-in scripts remain untrusted and run only in the gate sandbox.

### Candidate code escaping verification

**Threat:** Tests or build scripts access the network, credentials, Git state,
or unrelated host files, modify more than the candidate patch, or leave child
processes running.

**Mitigations:**

- Gates run in disposable worktrees at the exact base plus selected patch.
- The sandbox binds only required paths and denies network.
- A private `HOME`, temporary directory, and cache are used.
- Positive and negative probes cover worktree access and protected assets.
- Process-group timeouts cover descendants.
- Scope is rechecked after commands and full local output is hashed.

### Concurrent writers and state corruption

**Threat:** Concurrent tasks race on pointers, a worktree, acceptance, cleanup,
statistics, or shipping state; a crash leaves partial JSON.

**Mitigations:**

- At most one active/blocked build exists per common Git directory.
- Repository, run, and writer locks have a fixed acquisition order and bounded
  waits.
- Lock metadata excludes command arguments and environment values.
- Live locks block; stale-lock removal follows same-host PID or explicit
  foreign-host approval rules.
- State files use owner-private same-directory temporary writes, file `fsync`,
  atomic replace, and directory `fsync` where supported.
- Schemas reject unknown fields and illegal transitions.

### Stale candidate application

**Threat:** The orchestration branch advances after candidate creation and a
patch is applied to the wrong base.

**Mitigations:**

- Task and provider evidence record exact 40-character base commits.
- Patch applicability is proven against a clean checkout of that base.
- Acceptance checks the orchestration commit before applying.
- A fresh worktree independently verifies the selected patch.
- The applied scoped-tree hash must equal the verified tree byte-for-byte.

### Forged provider attribution

**Threat:** A caller uses a separate worktree registry, authors candidate bytes
without invoking Codex or Grok, and supplies a fabricated provider report so
the selection and commit history claim independent provider authorship.

**Mitigations:**

- Candidate creation, capture, selection, acceptance, and cleanup resolve the
  repository-common active run and reject every other registry.
- The active run's repository identity, current commit, active task, task base,
  and repository-ID prefix are rechecked for each lifecycle operation.
- `invoke` records the canonical run-evidence report path and hashes the exact
  validated report bytes on the candidate registry entry.
- External-provider capture revalidates those report bytes and requires the
  newly captured patch to have the report's exact patch hash.
- Selection parses only the digest-bound report bytes and requires its
  canonical path, provider, base commit, and patch hash to match the recorded
  candidate, then durably binds candidate path, report path, and report digest.
- Acceptance requires the candidate and evidence to equal that durable
  selection and revalidates the report and patch before applying anything.

### Worktree cleanup traversal or data loss

**Threat:** Cleanup follows a symlink, accepts a string-prefix collision,
removes an unrelated directory, or discards uncaptured changes.

**Mitigations:**

- Worktree paths are canonical, registry-backed, and contained beneath the
  configured canonical root.
- Existing parents cannot be symlinks.
- A captured dirty worktree requires exact reverse-patch proof and clean status.
- Cleanup uses ordinary `git worktree remove`; force removal and recursive
  deletion are forbidden.
- Incomplete proof retains the worktree and evidence.

### Token or sensitive-output leakage

**Threat:** Logs, terminal errors, manifests, reports, or consent prompts expose
OAuth tokens, environment values, secret findings, repository paths, or raw
provider output.

**Mitigations:**

- Crossforge never reads or manipulates provider tokens.
- Provider sessions remain owned by official CLIs.
- Raw output is owner-only evidence.
- User-facing errors are bounded and sanitized.
- Environment evidence contains names and value hashes, not values.
- Secret findings include only path, line, detector, and severity.
- Probe prompts contain no repository paths, remote, file names, or source.

### Accidental push or duplicate pull request

**Threat:** A normal build publishes source, a retry pushes twice or creates
duplicate PRs, hooks execute unsandboxed, or a changed target receives code.

**Mitigations:**

- The normal skill has no publication path.
- Shipping requires a completed run, direct invocation of the user-scoped
  shipping skill, and a fresh caller-attested publication-intent flag.
- Dry-run records no authorization and performs no writes.
- The normal, consent, and shipping skills expose disjoint CLIs; scoped host
  hooks block cross-surface and direct publication commands during supported
  execution.
- Authorization expires after 24 hours and binds repository identity, run,
  remote name and effective URL, head, target, final commit, preflight evidence,
  and an idempotency key.
- Write-time publication intent and a fresh final gate are required.
- PR title/body bytes are bounded and secret-screened before push; the forge
  executable path and hash are pinned and rechecked before every invocation.
- Remote head and matching open/closed PRs are read before writes.
- Pushes are non-force and disable hooks; required hook equivalents must be
  approved sandboxed gates.
- Remote and PR confirmations are persisted before the next step.
- Mismatched targets or commits require cancellation and a new
  caller-attested destination approval within the user-invoked shipping
  workflow.

**Residual risk:** A compromised forge CLI or server can lie about remote
state. Crossforge validates normal CLI readback but does not provide
cryptographic transparency for the forge.

## Symlink-specific policy

Symlinks are never followed during provider context enumeration. Every path
component is inspected. A provider-readable link must resolve inside the
candidate worktree. A changed symlink additionally requires an exact approved
`{path, target}` pair, and its normalized target must remain within the
candidate root. Parent symlinks, absolute targets, and traversal escapes block
the candidate.

## Availability and denial of service

Fail-closed behavior can block work when a provider CLI changes flags, a
sandbox probe is inconclusive, an executable changes identity, consent
expires, a lock owner crashes, or cleanup proof is unavailable. This is an
intentional availability tradeoff. Recovery preserves evidence and requires
caller-attested operator decisions where automated proof is insufficient.

Provider capability booleans are derived by the control layer, not accepted
from a caller-authored or model-writable result alone. The producer uses a
fresh nonce and fixed helper, then validates actual filesystem and
loopback-network effects. Codex uses the CLI's direct sandbox command, avoiding
a model-authored execution decision. Grok must emit an owner-private
control-host receipt for the exact helper command; absence or mismatch fails
closed. Helper, specification, hook, and hook-settings bytes are sealed and
rechecked after the run. Consent pins the canonical provider executable path
and hash, and the producer also refuses provider executables beneath
repository, state, or temporary roots. This makes the evidence a control-layer
observation; it does not protect against a compromised executable that the
operator explicitly approved, or a compromised authenticated provider CLI
host, which remain out of scope.

## Out of scope

- Protecting against a compromised operating system, kernel, Git binary,
  Python runtime, sandbox executable, or authenticated provider CLI host
- Guaranteeing that model-authored in-scope logic has no unknown semantic flaw
- Detecting a misaligned orchestrator that fabricates a schema-valid
  caller-attested decision where no forced user-confirmation hook exists
- Managing, rotating, backing up, or revoking provider/forge credentials
- Automatically merging, rebasing, deploying, or force-pushing
- Supporting repositories that require networked verification in MVP

## Security verification

The default test suite uses fake provider and sandbox executables and performs
no network request:

```text
python3 -m unittest discover -s tests -v
```

Release confidence additionally requires opt-in live sandbox/provider
capability tests described in [LIVE_TESTING.md](LIVE_TESTING.md). Do not treat
provider self-reporting as proof that a boundary holds.
