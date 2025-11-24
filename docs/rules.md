# Rules and Custom Rules

Configurations declare detections under two top-level arrays:

- `rules`: Datadog-supplied content shipped with the ruleset.
- `custom_rules`: Tenant- or agent-supplied additions.

Both arrays share the same schema. Entries are merged by ID; IDs must be unique across both arrays or the duplicate is rejected.
Rule actions referenced via `on_match` are resolved against the configuration’s action catalogue; see [Actions](actions.md).

## Rule schema

Required fields:

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Stable identifier. Must not collide with any other rule in the configuration set. |
| `name` | string | Human-readable label for diagnostics. |
| `tags` | object | Metadata emitted in events and used for grouping/overrides. Must include a `type` key; may include `module`, `category`, or any custom taxonomy. |
| `conditions` | array | Expression evaluated against request data. See the [Condition schema](conditions.md). |

Optional fields:

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Disable the rule without removing it. |
| `min_version`, `max_version` | semantic version | unrestricted | Load the rule only when the running libddwaf version falls within the range. |
| `transformers` | array | `[]` | Up to 10 identifiers applied to every input in the rule. See the [Transformer Reference](transformers.md). |
| `on_match` | array of strings | `[]` | Ordered list of action IDs to emit when the rule matches. See [Actions](actions.md) for the catalogue schema. |
| `output` | object | `{ event: true, keep: true, attributes: {} }` | Shape the emitted event; see below. |

### Tags and modules

- `tags.type` is required and typically mirrors the threat category (for example `sql_injection`, `lfi`, or `grpc_request_blocking`).
- `tags.module` is optional. Recognised values include `network-acl`, `authentication-acl`, `custom-acl`, `configuration`, `business-logic`, `rasp`, and `waf` (default). Modules control execution order and precedence (see `docs/overview.md`).
- Additional tags are free-form and surface in events; they can be used by overrides and exclusions for selection.

### Output object

The `output` object controls how matches surface:

- `event` (bool): when `false`, no event is produced.
- `keep` (bool): when `false`, the match may be dropped during sampling.
- `attributes` (object): map of extra fields to include in the result. Each value is either a static scalar (`value`) or a reference to request data via `address` and optional `key_path`.

Attribute entries support:

```json
{
  "attributes": {
    "static-example": { "value": "constant value" },
    "copied-field": {
      "address": "server.request.query",
      "key_path": ["user_id"]
    }
  }
}
```

- `value` accepts strings, integers, floats, and booleans.
- Referencing request data requires an `address` and an optional `key_path` (strings for map keys, integers for array indices). Omit `key_path` to copy the entire address.

Rules must generate at least one event or attribute. A rule with `output.event = false` and an empty `attributes` object is rejected during parsing.

Example:

```json
{
  "output": {
    "event": true,
    "keep": true,
    "attributes": {
      "user-id": { "address": "usr.id" },
      "static-tag": { "value": "auth" }
    }
  }
}
```

### Conditions and operators

Conditions use the shared expression schema documented in [conditions.md](conditions.md) and can reference any operator from the [Operator Reference](operators.md). Rule-level transformers apply to every input unless an input overrides them with its own `transformers` list.

### Evaluation notes

- Conditions operate on the request `values` data source by default and contribute matches to the rule event payload.
- Rule-level transformers run before the operator chain and apply to every input reference unless overridden at the input level.
- `on_match` actions fire in the order provided. Combine them with [exclusion filters](exclusions.md) to adjust the eventual verdict (`monitor`, `block`, or custom actions).
- Disabled rules, rules gated by incompatible versions, or rules filtered out by exclusions are skipped without evaluating their conditions.

## Example configuration

```json
{
  "version": "2.2",
  "actions": [
    { "id": "redirect-to-login", "type": "redirect_request", "parameters": { "location": "/login", "status_code": 303 } }
  ],
  "rules": [
    {
      "id": "ddos-rate-limit",
      "name": "Generic request flood",
      "tags": { "type": "configuration", "module": "waf" },
      "transformers": ["remove_nulls"],
      "conditions": [
        {
          "operator": "greater_than",
          "parameters": {
            "inputs": [{ "address": "server.request.rate" }],
            "type": "unsigned",
            "value": 200
          }
        }
      ],
      "on_match": ["block_request"]
    }
  ],
  "custom_rules": [
    {
      "id": "my-app-login-bruteforce",
      "name": "Login brute force detector",
      "tags": { "type": "security_scanner", "category": "auth", "module": "waf" },
      "conditions": [
        {
          "operator": "match_regex",
          "parameters": {
            "inputs": [{ "address": "server.response.body" }],
            "regex": "(?i)login failed"
          }
        }
      ],
      "on_match": ["monitor"],
      "output": {
        "event": true,
        "attributes": { "response_snippet": { "address": "server.response.body" } }
      }
    }
  ]
}
```

Both rule collections are parsed with the same validation rules: missing required fields or incompatible versions cause the entry to be skipped with diagnostics; rules that generate neither events nor attributes are rejected. Modules and precedence follow the execution order described in `docs/overview.md` (user-defined rules in `custom_rules` take precedence within modules that favour user content).
