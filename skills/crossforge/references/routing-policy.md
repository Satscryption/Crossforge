# Routing policy

Routing is deterministic policy plus recorded evidence. It does not grant a
provider consent or relax task limits.

## Explicit strategies

`codex`, `grok`, and `race` are fixed strategies. Honor one only when every
requested provider is enabled, available, consented for the operation, and
permitted by managed policy. Otherwise block clearly; never silently replace a
fixed lane.

## Automatic routing

- **Low risk:** use eligible benchmark-adaptive history; otherwise Codex is the
  cold-start default, with Grok preferred for configured mechanical classes.
  Do not race. Lean review is off by default.
- **Medium risk:** use one implementation lane and, when available, a different
  provider family for read-only review. Quality may race when gates provide a
  strong oracle.
- **High risk:** consult the commitment advisor and use a local read-only
  Claude plan critique. Release 0.1.1 does not call Codex or Grok in plan mode.
  During build execution, race only with objective comparison; otherwise use
  one implementation lane and the independently eligible review strategy
  recorded for the task.

The control layer directly invokes Codex and Grok. Do not route through a
Bash-capable Claude subagent. The Claude independent reviewer is used only when
Claude differs from the known author family. If authorship is unknown, record
that fact and do not claim family independence.

## Budget profiles

| Profile | Default behavior | Maximum provider invocations per task |
| --- | --- | ---: |
| `lean` | One lane; review high-risk work only | 4 |
| `balanced` | Review medium/high risk; race only eligible high-risk work | 6 |
| `quality` | Local high-risk plan critique; independent build-task review; race eligible medium/high-risk work | 8 |

External implementation, correction, and build-task review calls count. Local
Claude advisors do not count as provider invocations. The serialized
`planCritiqueLanes` compatibility field remains empty in 0.1.1 because no
external plan transaction exists. Stop before the limit. This is a
call/quality profile, not a monetary guarantee.

Automatic fallback is allowed only when `routing.json` records
`fallbackAllowed: true`; record the failed lane, failure category, replacement,
and reason. Fixed strategies require new user direction.

Adaptive promotion needs at least ten comparable eligible observations for
each provider in the same repository identity, schema major version, task
class, risk, and gate fingerprint. Compare only the most recent 50. Statistics
influence `auto` routing only.

Persist the decision through `route-task`, including selected strategy, review
strategy, reasons, and fallback policy. Candidate comparison then follows
[candidate selection](candidate-selection.md).
