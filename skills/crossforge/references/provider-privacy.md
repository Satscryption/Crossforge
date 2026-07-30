# Provider privacy and consent

Any repository- or user-controlled file readable by provider-issued tools is
transmitted context, whether or not it appears in the prompt. Provider
availability never implies consent.

## Before a remote call

1. Resolve the repository identity from the canonical root and normalized,
   credential-free origin URL.
2. Perform only local executable, version, help, and login-status checks before
   consent.
3. For remote readiness calls, obtain `probe` consent and send a fixed,
   source-free prompt with no repository path, remote, or file name.
4. Before source-bearing work, enumerate the complete provider-readable
   context, quarantine denied content, scan it, and use `prepare-consent` for
   the required operation class and exact manifest.
5. Show the sealed request summary, then stop. Only the user-invoked
   `/crossforge:crossforge-consent` skill may record the request; scripts never
   infer approval.

Consent is bound to repository identity, provider, operation classes, expiry,
the deny-policy hash, the discovered managed-policy hash, and the canonical
provider executable identity. A change to any binding invalidates it. The
short-lived request binds exact bytes and shows the user hash prefixes,
expiry, file count, and total bytes—never findings, contents, tokens, or
credential values. The normal model-invocable skill cannot call the approval
surface.

## Context preparation

- Match deny globs with Crossforge's fixed case-insensitive semantics. Move
  tracked matches to owner-only evidence and omit untracked matches.
- Manifest every remaining readable regular file and symlink with path, type,
  size, and SHA-256.
- Never follow symlinks; reject an escaping link or path component.
- Secret-scan readable text up to 10 MiB. Larger unscannable text blocks unless
  an unexpired local exception matches its exact hash.
- Quarantine binary files unless the approved task names their exact path and
  hash.
- Report secret findings only by path, line, detector, and severity.

Restore quarantined tracked paths byte-for-byte after all provider descendants
exit. A provider-created collision is restricted evidence and a scope
violation; do not run its gates.

## Execution boundary

Replace the linked-worktree Git control file with the one-commit sanitized Git
projection described in [worktree protocol](worktree-protocol.md). Provider
sandboxes must deny network to model-issued tools and deny the orchestration
checkout, common Git directory, credential directories, and unrelated user
files. Failed or inconclusive negative probes make that provider unavailable.

Pass subprocess arguments as arrays. Keep raw output in owner-only evidence;
surface only sanitized errors. Hash the exact task brief, context manifest,
redacted invocation, runtime manifest, and sandbox policy before invocation.
