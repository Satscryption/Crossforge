# Worktree protocol

Every implementation, race lane, micro-fix, review, and acceptance gate uses a
disposable recorded worktree. Candidate writers never touch the orchestration
checkout.

## Create and lock

Place worktrees beneath the canonical configured root, grouped by repository
identity prefix, run, and `<task-id>-<provider>`. Reject symlinked parents,
unrelated destination data, a wrong `HEAD`, or a dirty new worktree. Create a
detached worktree at the recorded base commit and add it to `worktrees.json`
before use.

Acquire an exclusive writer lock containing PID, hostname, provider, path, and
start time. Respect the lock order in [run state](run-state.md). A live lock
blocks; a foreign-host stale lock needs a caller-attested recovery approval.

## Quarantine and sanitized Git projection

Apply [provider privacy](provider-privacy.md), then:

1. move the linked-worktree `.git` control file to restricted evidence and
   record its hash and mode;
2. create an isolated repository with one baseline commit containing only
   context-manifest working-tree files;
3. use `Crossforge <crossforge@invalid>`, no remotes, no hooks, no credential
   helpers, no signing, no executable filters, no maintenance, no inherited
   Git configuration, and an owner-only temporary home;
4. prove that the isolated repository has no remote and exactly one commit;
5. record tree/commit IDs, effective sanitized configuration, executable
   identity, and sandbox-policy hash in `runtime-manifest.json`; omit
   placeholder evidence fields that are neither derived nor consumed.

After every provider descendant exits, record isolated Git metadata changes,
remove only the contained isolated `.git`, restore the original control file
and quarantined paths byte-for-byte, then calculate scope against the task
base. Failed restoration blocks the candidate and retains evidence.

## Capture

After scope passes, mark allowlisted untracked files intent-to-add and capture:

```text
git diff --binary --no-ext-diff <base-commit> --
```

Record the patch SHA-256, prove it applies to a clean base, clear intent-to-add
without changing working files, and confirm the hash is unchanged. Providers
never commit. For Codex and Grok candidates, first re-hash and validate the
canonical report written by `invoke`; after capture, require the patch hash to
equal the report's patch hash.

Selection then creates a fresh verification worktree at the recorded base,
applies that exact captured patch, and runs every durable task gate in order.
The control layer derives gate inputs and writes a hash-bound receipt; request
JSON cannot assert gate results or provenance.

Acceptance uses a fresh worktree at the same base: check and apply the exact
patch, re-check scope and the full diff, run gates in the sandbox, and hash the
verified scoped tree. Before doing so, require the selected candidate path,
invocation-report path, and report digest to equal the durable task selection,
then revalidate the report's provider, base, and patch. Only then may the
control layer apply that patch to a clean orchestration branch and require
byte-identical scoped-tree hashes. Candidate code never executes in the
orchestration checkout.

## Cleanup

Clean only a path recorded in `worktrees.json` whose canonical path is beneath
the configured root, after evidence is durable and no writer lock is active.
For a dirty captured candidate, first prove the exact patch reverses, reverse
it, and confirm a clean status before ordinary `git worktree remove`.

Never force-remove or recursively delete a candidate path. If containment,
patch reversal, cleanliness, or capture proof fails, mark it `retained`.
Cleanup remains available when provider exhaustion has blocked the active run
and task.
Allowed entry states are `creating`, `active`, `captured`, `retained`, and
`cleaned`.
