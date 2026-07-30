# Security review closeout

This document closes the security-review programme tracked by
[issue #16](https://github.com/Satscryption/Crossforge/issues/16). It maps
each finding to the implemented control and merged pull request. The code,
tests, durable evidence, and live-testing procedure remain authoritative; this
page is a traceability index rather than a new assurance claim.

## Final status

All linked findings, issues #3–#15, are remediated and closed. The final
documentation audit checked the README, build specification, architecture,
implementation decisions, threat model, live-testing guide, all three skill
contracts, every skill reference, and both read-only agent definitions against
the implemented command surfaces and tests.

Crossforge now uses four assurance labels consistently:

- **Control-verified:** derived from observed bytes, process effects,
  repository state, or remote readback.
- **User-confirmed:** provider consent forced by the supported host over a
  sealed control-generated disclosure.
- **Caller/model-attested:** structurally checked statements whose human
  provenance or semantic truth is not independently authenticated.
- **Provider claim:** untrusted provider-authored narrative or status.

## Finding disposition

| Finding | Implemented result | Merged PR |
| --- | --- | --- |
| [#3 Provider capability evidence had no producer](https://github.com/Satscryption/Crossforge/issues/3) | `record-capability` now runs a fixed, nonce-bound negative-probe producer after active-run-bound `probe` consent. It derives results from observed effects, seals helper/specification/hook bytes, rejects caller result paths and executable overrides, and requires a Grok control-host receipt. | [#18](https://github.com/Satscryption/Crossforge/pull/18) |
| [#4 Shipping did not re-derive repository identity or bind the remote URL](https://github.com/Satscryption/Crossforge/issues/4) | Shipping re-derives live repository identity, binds the exact effective fetch/push URL, rejects multiple or rewritten URLs, and rechecks the URL before every write. | [#17](https://github.com/Satscryption/Crossforge/pull/17) |
| [#5 Shipment authorization was replayable](https://github.com/Satscryption/Crossforge/issues/5) | Authorizations expire after 24 hours. Both authorization and recording require caller-attested publication intent, and write-time reconciliation reruns the final gate and validates the immutable tuple. | [#17](https://github.com/Satscryption/Crossforge/pull/17) |
| [#6 The local/publication boundary relied on prose](https://github.com/Satscryption/Crossforge/issues/6) | Normal, consent, and shipping skills have disjoint launchers and fail-closed host hooks. The normal CLI exposes no shipping command; `record-shipment` is the sole remote-write reconciler. | [#17](https://github.com/Satscryption/Crossforge/pull/17) |
| [#7 Provider consent was self-issuable](https://github.com/Satscryption/Crossforge/issues/7) | The normal skill can only prepare a byte-sealed, 15-minute request. The non-model-invocable consent skill revalidates live bindings and forces a host `ask` prompt over `consent_summary()` before recording. | [#19](https://github.com/Satscryption/Crossforge/pull/19) |
| [#8 PR body and forge execution could exfiltrate data](https://github.com/Satscryption/Crossforge/issues/8) | PR title/body bytes are bounded and secret-screened. The body must be an owner-private regular file in the run’s shipping evidence directory. The forge executable is resolved, path/hash pinned, and rechecked. | [#17](https://github.com/Satscryption/Crossforge/pull/17) |
| [#9 Repository configuration could weaken gate policy](https://github.com/Satscryption/Crossforge/issues/9) | Project policy may only add deny paths and narrow gate environment/executable allowlists. Credential-shaped environment names, including API/access keys, `DATABASE_URL`, and `KUBECONFIG`, are filtered after merging. | [#20](https://github.com/Satscryption/Crossforge/pull/20) |
| [#10 Candidate provider attribution was forgeable](https://github.com/Satscryption/Crossforge/issues/10) | Candidate lifecycle commands require the active run’s canonical registry and recheck repository/run/task/base bindings. External-provider capture, selection, and acceptance bind and revalidate the exact invocation-report path and digest. | [#21](https://github.com/Satscryption/Crossforge/pull/21) |
| [#11 Selection accepted caller-authored independent gate results](https://github.com/Satscryption/Crossforge/issues/11) | `record-selection` derives gates from durable task policy, replays the exact patch in a fresh worktree, records a descriptor-validated receipt, and is the only path into `candidate_ready`. Acceptance revalidates the receipt and reruns gates. | [#22](https://github.com/Satscryption/Crossforge/pull/22) |
| [#12 Recovery and shipping mutations could race](https://github.com/Satscryption/Crossforge/issues/12) | Multi-record recovery uses repository→run locking, exact before/after snapshots, transition validation, active-pointer checks, and terminal-state protection. Shipment recording and finalization use the same lock order and retry safely. | [#23](https://github.com/Satscryption/Crossforge/pull/23) |
| [#13 State commands accepted unrelated Git-common directories](https://github.com/Satscryption/Crossforge/issues/13) | Every state-facing CLI boundary discovers the supplied repository and requires exact common-Git-directory equality before reads, writes, or side effects. | [#24](https://github.com/Satscryption/Crossforge/pull/24) |
| [#14 Low-severity and informational findings](https://github.com/Satscryption/Crossforge/issues/14) | Deny globs are case-insensitive; context-manifest bytes are compared with canonical memory; dead mount evidence was removed; cleanup derives durability; scope failure exits 5; Git errors are sanitized; gate Git global options are rejected; micro-fix inputs are labeled caller-attested. | [#25](https://github.com/Satscryption/Crossforge/pull/25) |
| [#15 Documentation overstated model-authored proofs](https://github.com/Satscryption/Crossforge/issues/15) | Documentation and operator messages now distinguish byte/policy binding from human provenance, including plan approval, publication flags, recovery, and micro-fix semantics. | [#26](https://github.com/Satscryption/Crossforge/pull/26) |

## Release boundaries that remain

- Crossforge 0.1.0 invokes Codex and Grok only for active build tasks.
  Plan-mode critique and standalone review are local Claude workflows.
- The consent schema retains `plan` and routing retains
  `planCritiqueLanes` for forward compatibility. No 0.1.0 workflow prepares
  or invokes a `plan` transaction, and every routing decision leaves the lane
  list empty. External `review` consent applies only to active build tasks.
- Provider consent is user-confirmed. Plan semantics and `planApproval`,
  publication/destination flags, recovery decisions, and micro-fix semantic
  inputs remain caller/model-attested.
- The default suite uses fake provider, sandbox, and forge executables and
  performs no network request. There is no bundled automated live-test runner;
  `CROSSFORGE_LIVE_TESTS=1` is only an operator marker for the manual procedure.
  Follow [LIVE_TESTING.md](LIVE_TESTING.md) before trusting the alpha with
  valuable source or publication authority.
- A compromised operating system, sandbox binary, Git/Python runtime,
  authenticated provider CLI host, forge CLI, or forge server remains outside
  the stated threat model.

This documentation closeout PR is intended to close tracking issue #16 once
merged.
