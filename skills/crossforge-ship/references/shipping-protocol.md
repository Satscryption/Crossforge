# Shipping protocol

Shipping is a separate explicit-publication transaction. Ordinary Crossforge
planning, building, review, resume, and cleanup never call these operations.
The normal CLI does not expose them, and a skill-scoped host hook blocks access
to the shipping launcher. The shipping skill is user-invocable only and never
invokes remote-writing Git or forge commands directly.
`record-shipment` is the sole write reconciler.

## Preconditions

`ship-preflight` is read-only and must prove:

- the selected run is a completed build;
- no task is active, blocked, or incomplete;
- repository identity, checked-out branch, and `HEAD` match durable state;
- the orchestration checkout is clean;
- isolated final verification passed at the exact final commit;
- the remote and target match the approved plan, or the user approved the
  changed destination explicitly;
- the remote head is absent, exact, or a proven ancestor of the final commit;
- the remote target is a proven ancestor of the final commit.

An inconclusive ancestry check blocks. MVP does not update or rewrite history.
Shipping also fails closed on multiple URLs, distinct fetch/push destinations,
or active Git `url.*.insteadOf`/`pushInsteadOf` rules. Configure the selected
remote with one direct URL before preflight.

## Authorization

Authorization binds this immutable tuple:

```text
repository identity
run ID
remote
exact effective remote URL
head branch
target branch
final commit
```

It also records the bound preflight gate, a fixed 24-hour expiry, and a
random 32-lowercase-hex idempotency key. Repeating the same
authorization is idempotent only when the tuple and key both match. A mismatch
must not overwrite an unexpired record. After expiry, a fresh preflight,
current publication intent, and a new key may renew the exact tuple while
preserving any durable checkpoints. Cancel an unwritten authorization, obtain
explicit approval for any destination change, repeat preflight, and create a
new authorization.

`--dry-run` ends before this boundary. It writes neither authorization nor
remote state. `record-shipment` requires a fresh `--publication-requested`
assertion and rejects an expired authorization before any new external write.
Exact readback, checkpoint recovery, and terminal finalization remain available.

## Durable checkpoints

The transition is:

```text
none -> authorized -> remote_confirmed -> pr_confirmed -> recorded
                                      \-> push_only_recorded
```

On every `record-shipment` call and after every process restart, the control
layer—not the skill directly—queries remote state before deciding to write:

1. Validate the body, title, pinned forge executable, live repository identity,
   exact fetch/push URL, authorization expiry, current publication intent, and
   a fresh final gate before the first write.
   The body must be an owner-private regular file beneath the run's
   `evidence/shipping/` directory; arbitrary external paths and links fail.
2. If the remote head already equals the final commit, checkpoint
   `result: discovered`.
3. Otherwise require proven fast-forward ancestry, push once with hooks
   disabled and `--no-verify`, then require exact readback and checkpoint
   `result: performed`.
4. Query open and closed PRs for the exact head and target. Reuse one with
   `result: discovered`; if none exists, create one, read it back, and record
   `result: created`.
5. Mark the run shipped only after recorded state is independently read back.
   Shipment checkpoint validation, the terminal checkpoint write, and the run
   transition are serialized under `repository.lock` then `run.lock`. A retry
   after interruption preserves the first terminal `completedAt` and completes
   the run transition without repeating an external write.

A retained `performed` or `created` result is not downgraded to `discovered`
when a retry observes its prior write.

Never use force-push options. Never run repository hooks on the host. Never
claim a PR exists from create-command output alone. Never call `git push`,
`gh pr create`, or an equivalent external-write command outside
`record-shipment`.

## Cancellation

Cancellation is allowed only in `authorized` with null push and PR
checkpoints. Re-read the remote and forge first. If the exact final commit or a
matching PR exists, cancellation is unsafe and must stop for user handling.

Once a push is checkpointed—or remote readback indicates the final commit is
present—the authorization cannot be cleared automatically.
