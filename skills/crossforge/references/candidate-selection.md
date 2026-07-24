# Candidate selection

Use this protocol after every candidate has terminal evidence. Claude makes the
qualitative decision; the control CLI enforces eligibility and records it.

## Eligibility comes first

A candidate is ineligible if any of these is true:

- its base differs from the task base or its patch cannot apply there;
- exact scope, path, mode, symlink, submodule, special-file, or binary checks
  fail;
- any required sandboxed gate fails;
- the report or evidence hashes are invalid;
- it violates a plan guardrail or changes an unapproved public contract;
- generated or binary content is unexplained.

Do not weigh an ineligible candidate against an eligible one. Record the
hard-gate reason without exposing file contents or secrets.

## Compare eligible candidates

Consider, in order:

1. requirement completeness;
2. behavioral correctness;
3. test quality;
4. security properties;
5. interface fidelity;
6. repository convention alignment;
7. maintainability;
8. unnecessary complexity;
9. performance impact;
10. diff economy as a secondary factor.

Do not manufacture a numeric score for judgment. Provider claims are inputs,
not proof; prefer independently reproduced evidence.

Write `selection.md` with eligible candidates, hard-gate rejections, evidence
considered, the selected candidate, rationale, known weaknesses, and any
follow-up. Then use `record-selection`; acceptance remains a separate
control-layer operation.

Combining candidates requires a newly approved integration task. A correction
keeps the original allowlist and constraints, names the exact failed command,
and supplies only sanitized output. After three failed attempts by one provider,
block the task. A Claude micro-fix is allowed only after `check-micro-fix`
passes and must use a fresh recorded candidate worktree and the normal capture,
selection, and acceptance path.

See also [routing policy](routing-policy.md) and
[worktree protocol](worktree-protocol.md).
