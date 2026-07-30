---
name: crossforge-consent
description: Approve one sealed Crossforge provider-consent request after reviewing its exact non-sensitive disclosure. Use only when the user explicitly invokes this skill with the request path and SHA-256 produced by Crossforge.
compatibility: Requires a fresh consent request produced by the Crossforge control layer.
disable-model-invocation: true
hooks:
  PreToolUse:
    - matcher: "*"
      hooks:
        - type: command
          command: python3
          args:
            - "${CLAUDE_PLUGIN_ROOT}/hooks/crossforge_boundary.py"
            - consent
---

# Crossforge Consent

This user-only skill is the sole authority for turning a prepared provider
consent request into durable approval. The normal Crossforge skill can prepare
and disclose a request, but it cannot invoke this skill or record consent.

Canonical invocation:

```text
/crossforge:crossforge-consent --request <absolute-path> --request-sha256 <hex>
```

Run exactly:

```text
python3 "${CLAUDE_PLUGIN_ROOT}/skills/crossforge-consent/scripts/crossforge_consent.py" record-consent --request <absolute-path> --request-sha256 <hex> --json
```

Do not modify, recreate, or substitute the request. Do not call the normal
Crossforge or shipping launchers. The scoped hook validates the exact request
bytes and forces a Claude Code permission prompt whose user-only reason shows:

- provider and operation classes;
- repository, deny-policy, and managed-policy hash prefixes;
- canonical provider executable path and content-hash prefix;
- exact consent expiry;
- context file count and total bytes for source-bearing operations; and
- request identifier prefix.

If the user declines, the request expires, or any bound repository, policy,
executable, manifest, path, or request byte changes, stop without recording
consent. Never treat skill invocation, provider availability, or model text as
approval.
