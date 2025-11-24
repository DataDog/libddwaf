# Rule Overrides

Rule overrides adjust existing rules without redefining them. They live in the top-level `rules_override` array and are applied after rules/custom_rules are loaded.

## Schema

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `rules_target` | array | yes | Targets selected rules by `id`/`rule_id` or `tags`. |
| `enabled` | boolean | no | Forces enabled/disabled state. |
| `on_match` | string | no | Overrides the action to emit (for example `monitor` or a custom action ID). |
| `tags` | object | no | Additional tags to merge into the rule’s metadata. |
| `transformers` | array | no | Overrides the rule-level transformer list. |

An override must specify at least one mutating field (`enabled`, `on_match`, `tags`, or `transformers`).

### Targets

Each entry in `rules_target` accepts:

- `id` / `rule_id`: exact rule identifier.
- `tags`: object of tags to match (all key/value pairs must match).

### Behaviour

- Overrides are applied in order; later overrides replace earlier ones for the same rule attributes.
- Tag additions merge into the existing tag set.
- Providing `transformers` replaces the rule’s transformer list entirely.
- `on_match` replaces the rule’s action list; use exclusions for conditional bypass/monitor.

## Example

```json
{
  "rules_override": [
    {
      "rules_target": [{ "tags": { "type": "lfi" } }],
      "enabled": false
    },
    {
      "rules_target": [{ "rule_id": "crs-930-120" }],
      "on_match": "monitor",
      "tags": { "policy": "allowlist" }
    }
  ]
}
```
