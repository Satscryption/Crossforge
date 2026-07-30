# Canonical plan contract

`plan.json` is the only canonical plan. `plan.md` is a deterministic rendering
for people and is never parsed as authority. Convert an imported Markdown plan
to candidate JSON, validate it, show it to the user, and record approval of the
exact canonical JSON SHA-256 before initializing a build. The approval record
is model-attested: the control layer validates its schema and exact hash
binding but does not independently observe or authenticate the user's
response.

## Required plan shape

The schema version is `1`. Top-level data includes the objective and
user-visible outcome, context, assumptions, non-goals, architecture decisions,
security/privacy constraints, branch intent, non-empty global verification
commands, tasks, a decision log, and deferred work.

Each task requires:

- a unique `T[1-9][0-9]*` ID and acyclic dependencies;
- `low`, `medium`, or `high` risk and a task class;
- an exact, non-empty repository-relative file allowlist;
- an objective, constraints, interfaces, and non-empty `doneWhen`;
- non-empty verification commands;
- exact path and SHA-256 entries for approved binary context;
- exact path and in-worktree target entries for approved symlinks.

Gate commands are objects containing a non-empty `argv` array and a timeout.
They never contain shell syntax. Reject inline interpreter code, destructive
operations, privilege changes, credential operations, publishing, and remote
writes. Candidate-controlled scripts still run only in the gate sandbox.

## Approval and materialization

Use `validate-plan`, `render-plan`, and `materialize-tasks`. Deterministic code
may validate and add runtime fields but must not infer product meaning. Any
change to canonical JSON invalidates approval, even when it appears stricter.
The approved hash stored in run state must equal the current canonical bytes.
That equality proves byte consistency, not human provenance.

`shippingIntent` is either `local-only` or
`publish-on-later-explicit-request`; neither authorizes publication. A
multi-task plan is invalid with `--no-commit`.

Classify authentication, authorization, security controls, payments,
cryptography, destructive persistence, concurrency, public API compatibility,
data loss, and downtime-sensitive infrastructure as high risk. When uncertain,
classify upward.

See also [task briefs](task-brief.md), [routing policy](routing-policy.md), and
[run state](run-state.md).
