# Exclusion Filters

Exclusions refine how rules respond to specific traffic without editing the rules themselves. Two flavours exist:

- **Rule exclusions** change the verdict of matching rules.
- **Input exclusions** remove request fields from rule evaluation while leaving the rule active.

Both live in the `exclusions` array of a configuration and share the same top-level shape.

## Shared schema

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | string | yes | Unique identifier for diagnostics and deduplication. |
| `min_version`, `max_version` | semantic version | no | Restrict the exclusion to specific libddwaf versions. |
| `conditions` | array | no | Expression evaluated against request data. See the [Condition schema](conditions.md). Omit for unconditional exclusions. |
| `rules_target` | array | no | List of rules to affect. Entries may include `rule_id`/`id` (exact match) or `tags` for tag-based selection. Omit to target all rules. |

At least one of `conditions`, `rules_target`, or `inputs` (for input exclusions) must be provided; otherwise the entry is rejected.

## Rule exclusions

Additional field:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `on_match` | string | no | Outcome when the exclusion triggers: `bypass` (default, skip rule entirely), `monitor` (force monitor verdict), or a custom action ID from the [action catalogue](actions.md). |

Use rule exclusions to silence noisy rules, force monitoring, or reroute matches to a custom action.

### Example

```json
{
  "id": "skip-log4shell-on-backend",
  "conditions": [
    {
      "operator": "match_regex",
      "parameters": {
        "inputs": [{ "address": "server.address" }],
        "regex": "^10\\."
      }
    }
  ],
  "rules_target": [{ "rule_id": "log4shell" }],
  "on_match": "bypass"
}
```

## Input exclusions

Additional field:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `inputs` | array | yes | Addresses (and optional key paths) to remove from rule evaluation when the exclusion matches. |

Each entry inside `inputs` accepts:

| Key | Type | Required | Notes |
| --- | --- | --- | --- |
| `address` | string | yes | Address to prune (for example `server.request.query`). |
| `key_path` | array of strings | no | Navigate into nested structures; use `"*"` as a wildcard. Omit to remove the entire address. Missing segments are treated as wildcards. |

Input exclusions let rules keep running but with sensitive or noisy fields removed.

### Example

```json
{
  "id": "ignore-debug-parameter",
  "inputs": [
    { "address": "server.request.query", "key_path": ["debug"] }
  ],
  "rules_target": [
    { "tags": { "type": "security_scanner" } }
  ]
}
```

## Evaluation notes

- Unique `id` values are enforced. Entries with incompatible version bounds are skipped.
- Exclusions run before rule evaluation. The first match is memoised for the rest of the request to keep lookups fast.
- Rule exclusions decide the final verdict (`bypass`, `monitor`, or custom action). Input exclusions prune data and allow the rule to produce a normal outcome on the reduced input.
- Combine exclusions with rule `on_match` actions to tune blocking/monitoring decisions without modifying the rule logic.
