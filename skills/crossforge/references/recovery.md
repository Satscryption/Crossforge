# Recovery

Resume is validation, not reconstruction from conversation memory. Use the
control CLI and durable repository-common state.

## Resume sequence

1. Resolve the absolute common Git directory and orchestration Git directory.
2. Read `active`, then validate every canonical JSON file for that run.
3. Confirm repository identity, orchestration checkout, branch, and recorded
   commit.
4. Confirm the last committed task matches `HEAD`.
5. Inspect `activeTaskId`, task status, attempts, and evidence.
6. Validate all recorded candidate and verification worktrees.
7. Validate repository, run, and writer locks in required acquisition order.
8. Re-run scope checks for an in-progress candidate.
9. Re-probe the gate sandbox and recorded provider capabilities.
10. Recompute the canonical plan hash and validate its approval binding.
11. Report the exact recovery point and blockers before continuing.

Stop without modifying state when `HEAD`, identity, schema, plan approval,
sandbox policy, worktree evidence, or a live writer lock is inconsistent.
Never guess, overwrite evidence, discard changes, or clear a foreign-host lock.
A same-host stale lock may be cleared only after proving its PID is absent; a
foreign-host lock requires explicit user approval.

Blocked tasks resume only after the blocker and user-approved recovery decision
are appended to `decisions.md`. Use normal transition commands rather than
editing JSON. `status` is strictly read-only and reports provider availability
as the last recorded probe.

If recovery is intentionally abandoned, use `abandon-run`; do not delete its
evidence. Cleanup follows the containment and captured-patch proof in
[worktree protocol](worktree-protocol.md). Retain a worktree whenever cleanup
proof is incomplete.

See [run state](run-state.md) for pointers and transitions.
