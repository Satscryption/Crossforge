# Crossforge

Claude architects. Independent models build. Evidence decides.

Crossforge is a Claude Code plugin for planning and executing multi-task
software changes with OpenAI Codex and xAI Grok in isolated candidate
worktrees. Claude supplies product judgment and selects among eligible
candidates; a standard-library-only Python control layer enforces plan
approval, provider consent, exact file scope, sandboxed verification, durable
state, and local commits.

Crossforge does not approve provider access or push during its normal
model-invoked workflow. Provider consent and publishing are separate,
user-invoked `crossforge-consent` and `crossforge-ship` operations.

> Crossforge 0.1.0 is an alpha release. Its offline suite uses fake provider,
> sandbox, and forge executables. No real provider call or publication is made
> by the default tests; complete the opt-in checks in
> [Live testing](docs/LIVE_TESTING.md) before relying on it with valuable
> source code.

## How it works

```text
User
  -> Claude architect
      -> deterministic Crossforge control layer
          -> sealed consent request
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

Each provider gets a separate detached worktree and a self-contained approved
task brief. Before source is exposed, Crossforge quarantines denied paths,
rejects or explicitly approves binary context, scans all provider-readable
text, records a complete context manifest, and replaces the linked-worktree
Git control file with a sanitized one-commit repository. Provider tools are
confined by their CLI sandbox.

After a provider exits, Crossforge restores trusted files, calculates the exact
diff against the recorded base, and runs verification in a fresh disposable
worktree inside a separate network-denied gate sandbox. Provider reports are
claims; only independently reproduced scope and gate evidence makes a
candidate eligible. See [Architecture](docs/ARCHITECTURE.md) and the
[Threat model](docs/THREAT_MODEL.md).

## Requirements

- Claude Code 2.1.216 or newer
- Python 3.11 or newer
- Git 2.39 or newer
- macOS, Linux, or WSL
- `sandbox-exec` on supported macOS versions, or Bubblewrap (`bwrap`) on
  Linux/WSL, for build and ship modes
- At least one optional implementation provider:
  - OpenAI Codex CLI, authenticated with `codex login`
  - xAI Grok CLI, authenticated with `grok login`
- GitHub CLI (`gh`) when creating GitHub pull requests

Planning, status, and local inspection can still work without a provider or
gate sandbox. A fixed unavailable provider strategy fails clearly; Crossforge
never silently substitutes another provider.

The Python runtime has no third-party package dependencies. Provider, Git,
forge, and sandbox executables are capability-probed external tools.

## Installation

The repository root is the plugin and marketplace root—the directory containing
`.claude-plugin/plugin.json`. After cloning the repository, add that directory
as a local marketplace and install the plugin:

```text
git clone https://github.com/Satscryption/Crossforge.git
cd Crossforge
claude plugin marketplace add .
claude plugin install crossforge@crossforge
```

The equivalent interactive Claude Code commands are:

```text
/plugin marketplace add /absolute/path/to/Crossforge
/plugin install crossforge@crossforge
```

Restart Claude Code or reload plugins after installation. The canonical skill
names are:

```text
/crossforge:crossforge
/crossforge:crossforge-consent
/crossforge:crossforge-ship
```

Bare aliases may appear when no installed skill collides with them; automation
should use the canonical names.

Authenticate provider CLIs separately. Crossforge invokes their existing
sessions and never reads, copies, or refreshes their tokens:

```text
codex login
grok login
gh auth login
```

## Quick start

From a clean Git checkout, ask for a plan first:

```text
/crossforge:crossforge --mode plan --budget balanced
Plan an implementation of per-user API rate limits.
```

Review the canonical `plan.json` rendering and explicitly approve its exact
hash. Then build:

```text
/crossforge:crossforge --mode build --strategy auto --budget balanced
Build the approved plan.
```

Useful alternatives:

```text
/crossforge:crossforge --mode review
/crossforge:crossforge --mode status
/crossforge:crossforge --mode resume
/crossforge:crossforge --mode build --strategy codex --no-commit
```

`--no-commit` is restricted to a one-task plan. Build tasks otherwise execute
serially and produce local task commits on a dedicated branch. Nothing is
pushed.

To publish a completed run, make a separate explicit request:

```text
/crossforge:crossforge-ship --run-id <run-id> --remote origin \
  --target-branch main --draft --dry-run
```

Remove `--dry-run` only after checking the proposed immutable publication
tuple. The user-invoked shipping skill has a dedicated CLI; the normal CLI has
no shipping commands. Shipping binds the effective remote URL, expires
authorization after 24 hours, re-runs the final gate at write time, screens
the PR title/body, pins the forge executable, never force-pushes, and discovers
an existing matching remote commit or pull request before writing.

## Modes

| Mode | Purpose |
| --- | --- |
| `plan` | Produce, validate, render, and hash a canonical structured plan; 0.1.0 uses local Claude critique only. |
| `build` | Execute an approved plan in isolated lanes and make local commits. |
| `review` | Perform an evidence-backed local read-only review; cross-vendor standalone review is deferred. |
| `resume` | Validate durable state and continue an interrupted build. |
| `status` | Read durable status without creating or changing a run. |

Strategies are `auto`, `codex`, `grok`, and `race`. Explicit strategies are
fixed requests and block if unavailable. `auto` follows risk, task class,
provider availability, consent, and comparable local evidence.

Budgets are call/quality profiles, not spending guarantees:

| Budget | Default behavior | Provider calls per task |
| --- | --- | ---: |
| `lean` | One lane; review high-risk work only | 4 |
| `balanced` | Review medium/high risk; race only eligible high-risk work | 6 |
| `quality` | Independent critiques; race eligible medium/high-risk work | 8 |

## Provider consent and source transmission

Provider installation or authentication is not consent. Crossforge requests
repository-bound, provider-specific, expiring approval for operation classes:
`probe`, `plan`, `review`, and `implement`.

A remote readiness call needs `probe` consent and uses a fixed source-free
prompt. A source-bearing call additionally shows the provider, operation
classes, repository identity prefix, deny-policy and managed-policy hash
prefixes, expiry, context file count, and total bytes. Crossforge never prints
secret values in this prompt.

The normal skill can only run `prepare-consent`, which derives these facts,
writes a private request with a 15-minute approval window, and returns its
exact byte hash. It then stops. Only the explicitly user-invoked
`/crossforge:crossforge-consent` skill can submit that request to
`record-consent`. Its hook revalidates the request, repository, policy,
provider executable, and context-manifest bindings and forces a user
permission prompt containing the disclosure. The normal skill cannot call the
approval launcher or use file-mutation/subagent tools, and the approval skill
allows only its single canonical consent transaction.

Consent becomes invalid when the repository identity, provider, operation
class, expiry, deny policy, local exceptions, provider-visible context policy,
detected managed policy, or operator-approved provider executable path/hash
changes. Provider-readable files count as transmitted context even if the
prompt does not mention them.

Provider capability evidence is not an operator-authored checklist.
After repository-bound `probe` consent is valid, `record-capability` resolves
the exact executable pinned when consent was recorded, runs a fresh source-free
negative-probe transaction, and derives each sandbox result from observed
filesystem and loopback-network effects. Codex runs the fixed helper directly
through `codex sandbox`, with no model-authored result path. Grok requires an
owner-private control-host hook receipt for the exact helper command. The
parent also re-hashes the helper, sealed specification, hook, and hook settings
after execution. It accepts neither an evidence file nor an executable
override. Failed, skipped, forged, mutated, partial, or stale probe inputs
leave the provider unavailable.

## Configuration

Configuration precedence, highest first:

1. Invocation arguments
2. `.claude/crossforge.json`
3. `~/.claude/crossforge.json`
4. Safe defaults

Objects merge recursively. Arrays replace the lower-precedence array in full.
Unknown keys, invalid enum values, and out-of-range values are errors.
Because project configuration is repository-controlled, three security fields
are tighten-only relative to user configuration and safe defaults:
`gateEnvironmentAllowlist` and a non-empty
`gates.executableAllowlist` may only shrink, while `denyPaths` may only grow.
An empty executable allowlist means the exact executables approved in
`plan.json`, so a project may replace that implicit set with a narrower
explicit restriction. Gate construction intersects every explicit executable
list with the plan-approved basenames, so repository policy cannot add
execution authority.

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
  "architect": {
    "lean": "opusplan",
    "balanced": "opusplan",
    "quality": "fable",
    "highRisk": "fable",
    "fallback": "opusplan"
  },
  "microFix": {
    "enabled": true,
    "maximumChangedLines": 5
  },
  "commits": {
    "enabled": true
  },
  "consent": {
    "ttlDays": 90
  },
  "gates": {
    "timeoutSeconds": 900,
    "sandboxBackend": "auto",
    "network": "deny",
    "executableAllowlist": []
  },
  "routing": {
    "minimumEvidenceTasks": 10,
    "grokPreferredClasses": [
      "boilerplate",
      "fixtures",
      "repetitive-wiring",
      "crud",
      "straightforward-ui"
    ]
  },
  "retention": {
    "keepWorktrees": false
  },
  "denyPaths": [
    "**/.env",
    "**/.env.*",
    "**/secrets/**",
    "**/*credential*",
    "**/*private-key*",
    "**/*.pem",
    "**/*.p12",
    "**/*.key"
  ],
  "gateEnvironmentAllowlist": [
    "PATH",
    "LANG",
    "LC_ALL",
    "CI"
  ]
}
```

Provider and gate timeouts must be 10–7200 seconds, consent TTL 1–365
days, and micro-fix size 0–10 changed lines. Gate network policy is always
`deny`. A non-empty gate executable allowlist further restricts—not expands—
the exact executables approved in `plan.json`.
Credential-shaped environment names are removed even if allowlisted,
including API/access keys, tokens, secrets, authentication variables,
`DATABASE_URL`, and `KUBECONFIG`.

## State, worktrees, and evidence

Durable state is stored outside the working tree:

```text
<absolute-git-common-dir>/crossforge/
```

It contains repository consent, short-lived unapproved consent requests,
provider statistics, locks, `active` and `latest-complete` pointers, and a
directory per run. Run records include the canonical plan and approval hash,
task state, decisions, interfaces, worktree registry, shipment checkpoints,
and owner-only evidence. Do not edit these files by hand.

Candidate worktrees default to:

```text
${CROSSFORGE_WORKTREE_ROOT:-${TMPDIR:-/tmp}/crossforge-worktrees}/
  <repository-id-prefix>/<run-id>/<task-id>-<provider>/
```

Use `--keep-worktrees` or `retention.keepWorktrees` for diagnostics. Cleanup
never force-removes a worktree: it validates the recorded canonical path,
proves a captured patch reverses exactly, confirms cleanliness, and uses
ordinary `git worktree remove`. Failed proof retains the worktree.

Raw provider stdout/stderr and patches remain owner-only local evidence. They
may contain sensitive source or provider output; do not publish the Git-common
state directory.

## Recovery

Use status first, then resume:

```text
/crossforge:crossforge --mode status
/crossforge:crossforge --mode resume
```

Resume reloads the `active` run and validates repository identity, checkout,
branch, `HEAD`, schemas, plan hash and approval, task state, candidate
worktrees, locks, scope, provider capabilities, and sandbox probes. It stops on
inconsistency instead of reconstructing state from chat or discarding changes.

A blocked task can resume only after its blocker and a user-approved recovery
decision are appended to the durable decision log. Use `abandon-run` through
the control workflow when abandoning; evidence is retained.

See [Recovery and cleanup](skills/crossforge/references/recovery.md) for the
full protocol.

## Troubleshooting

### “Python 3.11 or newer is required”

The executable running Crossforge is too old even if another Python is
installed. Check `python3 --version` and make the 3.11+ executable available
through an absolute-component-only `PATH`.

### “PATH contains an empty or relative component”

Remove empty entries (`::`, a leading/trailing separator) and relative
directories such as `.`. Crossforge resolves and records gate executables
before approval.

### “No supported sandbox backend”

Build and ship fail closed without `sandbox-exec` on supported macOS systems or
`bwrap` on Linux/WSL. Installation alone is insufficient: positive and
negative capability probes must pass.

### Provider unavailable or authentication failed

Run `codex login status`, or `grok models` after `grok login`. Crossforge also
requires compatible non-interactive safe flags and proven sandbox denial. It
does not downgrade to blanket approval or unsafe access.

### Consent is requested again

This is expected after expiry or any repository, operation, deny-policy,
exception, context-policy, or managed-policy change. Approval binds the exact
transmission policy, including stricter changes.

### Scope violation or secret-policy failure

Inspect sanitized evidence paths and task allowlists; secret values are
intentionally not printed. Change the approved plan or local exact-hash
exception rather than bypassing the check.

### Cleanup retained a worktree

Crossforge could not prove containment, patch reversibility, or cleanliness.
Preserve the directory and evidence, inspect it manually, and do not
force-delete through Crossforge.

### Shipping stopped after a network interruption

Retry the same shipping request. Shipment authorization and remote/PR
checkpoints are idempotent; Crossforge reads remote state before another
write. Do not change remote, head, target, or commit under an existing
authorization.

## Development and verification

From this directory, using a Python 3.11+ interpreter:

```text
python3.11 -m unittest discover -s tests -v
python3.11 -m json.tool .claude-plugin/plugin.json
python3.11 -m json.tool .claude-plugin/marketplace.json
```

The sources use 3.10+ syntax, so a bare `python3` that resolves to an older
interpreter (for example the 3.9 shipped with macOS Command Line Tools) fails
to import the test modules. Invoke an explicit 3.11+ interpreter, or put one
first on `PATH`, so both these commands and the plugin's own `python3` launcher
resolve it. At runtime the control layer also fails closed with a clear
"Python 3.11 or newer is required" message if the launcher is too old.

The unit suite requires no provider credentials or network. Real-provider
checks are opt-in; follow [Live testing](docs/LIVE_TESTING.md).

## License and provenance

Crossforge is MIT licensed. It is an independent implementation informed by
the interaction design of Dan McAteer’s MIT-licensed
[fable-advisor](https://github.com/DannyMac180/fable-advisor); its notice is
preserved in [Third-Party Notices](THIRD_PARTY_NOTICES.md).

The previously mentioned `codex-build` name has no uniquely verified source;
Crossforge does not copy or attribute code to it. Crossforge is not endorsed by
Anthropic, OpenAI, or xAI.
