# Rule Definitions

Rules describe the detections performed by libddwaf. They live inside either the
`rules` array (Datadog-maintained content) or `custom_rules` (user-supplied
additions) within a configuration document. Each entry declares the conditions
to inspect in the request, the metadata attached to any matches, and the
actions that should follow.

## Required structure

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | yes | Stable identifier. Must be unique across all rules (base and custom). |
| `name` | string | yes | Human-readable label shown in diagnostics. |
| `tags` | object | yes | Metadata used for grouping, routing, and overrides. Must include a `type` key (for example `"type": "lfi"`). Optionally include `category`, `module`, or any other taxonomy keys you rely on. |
| `conditions` | array | yes | List of condition objects describing the match logic. See the [Operator Reference](operators.md) for supported operators and parameter schemas. |

## Optional common fields

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `enabled` | boolean | `true` | Disable a rule without removing it from the document. |
| `min_version`, `max_version` | semantic version | unrestricted | Restrict the rule to specific libddwaf versions. |
| `transformers` | array | empty | Sequence of transformer identifiers applied to all inputs referenced by the rule before conditions run. See the [Transformer Reference](transformers.md). At most 10 entries are accepted. |
| `on_match` | array of strings | empty | Ordered list of action identifiers to emit when the rule matches. Actions are resolved at runtime through the ruleset's action catalogue. |
| `output` | object | implicit event+keep | Fine-tune the generated event and attributes. Details below. |

### Tags and modules

- `tags.type` is required and typically mirrors the threat category (for example
  `sql_injection`, `lfi`, or `grpc_request_blocking`).
- `tags.module` is optional. When present it controls rule grouping inside the
  engine. Recognised values include `network-acl`, `authentication-acl`,
  `custom-acl`, `configuration`, `business-logic`, `rasp`, and `waf` (default).
- Additional tags are free-form and can be used to express application, service,
  or platform metadata. They are emitted in rule events and are also available
  to rule overrides or filters via tag-based selectors.

## Output controls

The `output` object lets you shape the payload returned when a rule matches:

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `event` | boolean | `true` | When `false`, the rule does not generate an event. Combine with attributes to create silent annotation rules. |
| `keep` | boolean | `true` | When `false`, the rule outcome may be dropped during sampling. Leave enabled when the match should always be preserved. |
| `attributes` | object | `{}` | Map of additional fields attached to the rule result. Each entry accepts either a static `value` or a reference to request data via `address`/`key_path`. |

Attribute entries support two shapes:

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
- Referencing request data requires an `address` and an optional `key_path`.
  Each element in `key_path` is either a string (map key) or an integer (array
  index). Omit `key_path` to copy the entire address.

Rules must generate at least one event or attribute. A rule with
`output.event = false` and an empty `attributes` object is rejected during
parsing.

## Rule evaluation overview

- Conditions operate on the request `values` data source. Each condition
  contributes matches that are collected in the rule's event payload.
- Transformers listed at the rule level run before the operator chain and apply
  to every input reference in the rule.
- `on_match` actions fire in the order provided. Combine them with
  [exclusion filters](exclusions.md) to tune the eventual verdict
  (`monitor`, `block`, or custom actions).
- Disabled rules, rules gated by incompatible versions, or rules filtered out by
  exclusions are skipped without evaluating their conditions.

## Example rule

```json
{
  "id": "my-app-login-bruteforce",
  "name": "Login brute force detector",
  "tags": {
    "type": "security_scanner",
    "category": "misc_checks",
    "module": "waf",
    "service": "frontend"
  },
  "transformers": ["remove_nulls"],
  "conditions": [
    {
      "operator": "match_regex",
      "parameters": {
        "regex": "(?i)login failed",
        "inputs": [
          { "address": "server.response.body" }
        ]
      }
    }
  ],
  "on_match": ["block_request"],
  "output": {
    "event": true,
    "keep": true,
    "attributes": {
      "response_body": {
        "address": "server.response.body",
        "key_path": []
      }
    }
  }
}
```

This example inspects the response body for an authentication failure pattern,
ensures the match is always kept, and attaches the full response body to the
generated event while instructing the engine to trigger the `block_request`
action.
