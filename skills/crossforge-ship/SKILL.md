---
name: crossforge-ship
description: Ship a completed Crossforge run by revalidating its recorded evidence, running the final repository gate, pushing its branch, and opening or reusing exactly one pull request when a supported forge CLI is available. Use only when the user explicitly asks to push, publish, ship, or open a PR for completed Crossforge work.
compatibility: Requires a completed Crossforge run, Git, and a configured forge CLI such as gh.
disable-model-invocation: true
hooks:
  PreToolUse:
    - matcher: "Bash"
      hooks:
        - type: command
          command: python3
          args:
            - "${CLAUDE_PLUGIN_ROOT}/hooks/crossforge_boundary.py"
            - ship
---

# Crossforge Ship

Ship only through the deterministic control layer. This skill is the sole
Crossforge authority for external repository writes.

Never run `git push`, `gh pr create`, or another remote-writing Git/forge
command directly. `record-shipment` is the sole write reconciler: it owns
read-before-write push and pull-request behavior plus every durable checkpoint.

Canonical invocation:

```text
/crossforge:crossforge-ship [--run-id ID] [--remote NAME] [--target-branch NAME] [--draft] [--dry-run]
```

Only a user may invoke this skill. Run its dedicated control surface:

```text
python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge-ship/scripts/crossforge_ship.py" <subcommand> [options]
```

Reject unknown arguments. Read
[the shipping protocol](references/shipping-protocol.md) before acting.

## Required sequence

1. Confirm that the current user request explicitly asks for publication.
2. Run `ship-preflight`. It must load a completed build, reject active or
   blocked tasks, confirm the recorded branch and commit, require a clean
   checkout, recreate isolated final verification, and run the canonical
   structured global gate in the gate sandbox.
3. Resolve the remote and target from explicit arguments or the approved plan.
   A mismatch requires explicit approval and a new preflight.
4. Let `ship-preflight` read the remote head and target. Stop on divergence;
   never pull, merge, rebase, or force push. `ship-preflight` itself creates a
   fresh verification worktree, runs the canonical global commands, and binds
   the resulting independent evidence to the run and final commit. Assert
   current publication intent with `--publication-requested`.
5. With `--dry-run`, report the returned plan and stop. Do not call
   `authorize-shipment` or `record-shipment`.
6. Otherwise generate a random 32-lowercase-hex idempotency key and call
   `authorize-shipment --publication-requested --idempotency-key <key>` with
   the same run, remote, and target used by preflight. Authorization re-runs
   the trusted shipping preflight; caller-supplied gate results are never
   accepted. This skill—not the main Crossforge skill—owns that authorization.
7. Prepare an owner-private PR body file beneath the selected run's
   `evidence/shipping/` directory containing the required summary, then
   call `record-shipment --publication-requested --run-id <id> --body-file <path> [--draft]`.
   `record-shipment` must re-read the remote, push only when needed with hooks
   disabled, durably checkpoint readback, query open and closed matching PRs,
   create at most one, read it back, and record completion.
8. If no supported forge CLI exists, call
   `record-shipment --publication-requested --run-id <id> --push-only`; report
   compare-URL instructions
   without claiming a PR exists.
9. Report the durable branch, commit, PR URL when present, and whether each
   result was performed, created, or discovered.

Retries resume from `shipment.json` and always read before writing. Never edit
shipping state by hand. Cancellation is permitted only before any external
write and only after readback proves the final commit and matching PR are
absent.

The PR body must summarize context, task commits, independently reproduced
test evidence, known risks, and deferred work. Provider claims are not test
evidence.
