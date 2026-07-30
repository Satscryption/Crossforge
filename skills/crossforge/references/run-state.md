# Run state

Crossforge state is repository-scoped and lives under:

```text
<absolute-git-common-dir>/crossforge/
```

Never place it in a linked worktree's private Git directory or commit it as
product code. Record the orchestration Git directory separately in `run.json`.
Directories are owner-only (`0700`) and files are owner-only (`0600`), subject
to umask. Canonical writes use same-directory temporary files, file `fsync`,
atomic replacement, and directory `fsync` where supported.

## Pointers and modes

`active` contains the one unfinished build run ID. `latest-complete` contains
the newest completed, unshipped build run ID. Plan and review write terminal
run evidence but claim neither pointer. Status creates no run. Resume operates
on a build run and is not a stored mode.

Run IDs are `YYYYMMDDTHHMMSSZ-` plus eight random lowercase hexadecimal
characters. A new build is blocked while `active` names an active or blocked
run.

## Run transitions

```text
active -> blocked | complete | abandoned
blocked -> active | abandoned
complete -> shipped
```

`shipped` and `abandoned` are terminal. Plan/review runs may only become
`complete` and are not shippable.

## Task transitions

```text
pending -> in_progress | blocked
in_progress -> candidate_ready | blocked
candidate_ready -> accepted | blocked
accepted -> committed | complete | blocked
committed -> complete | blocked
blocked -> in_progress
```

`complete` is terminal. A no-commit run has exactly one task and transitions
from `accepted` to `complete`.

Use `init-run`, `start-task`, `record-selection`, `accept-candidate`,
`finish-task`, `complete-run`, and `abandon-run` for state changes. Never edit
canonical JSON or pointers by hand. Transition commands are idempotent only
when the complete existing target record matches.

Every state command is repository-bound. Supply the orchestration repository
alongside an explicit Git common directory, and stop if the control layer says
they do not resolve to the same repository. Never retry with a different
repository merely to make a state path pass validation.

## Locks and consistency

Acquire locks only in this order:

```text
repository.lock -> run.lock -> writer.lock
```

Repository locking covers pointer changes, acceptance, provider statistics,
cleanup, and shipping checkpoints. Run locking covers run transitions; writer
locking protects one candidate worktree. Never wait for an earlier lock while
holding a later one.

`complete-run` durably completes the run, updates `latest-complete`, then
removes `active`. Shipping uses an explicit run ID or `latest-complete`, and
its checkpoints are separate from ordinary build state.

See [recovery](recovery.md) for consistency checks and
[worktree protocol](worktree-protocol.md) for writer records.
