# Exclusion Filters

Exclusions let you refine how a ruleset responds to specific situations without
editing the rules themselves. They are defined in the `exclusions` array of a
configuration payload and come in two flavours:

- **Rule exclusions** change the verdict of matching rules.
- **Input exclusions** remove particular request fields from consideration while
  the rule logic still runs.

Both types share a common structure and can be combined in the same document.

## Shared fields

Every exclusion object accepts the following keys:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `id` | string | yes | Unique identifier for diagnostics and deduplication. |
| `min_version`, `max_version` | semantic version | no | Restrict the exclusion to specific libddwaf versions. |
| `conditions` | array | no | Expression evaluated against request values. When omitted the exclusion is unconditional. |
| `rules_target` | array | no | List of rules to affect. Each entry can provide `id`/`rule_id` (exact rule identifier) or a `tags` object to match by tag set. Omit to target every rule. |

An exclusion must provide at least one of `conditions`, `rules_target`, or
`inputs` (for input exclusions). If all of them are omitted the entry is
rejected.

## Rule exclusions

A rule exclusion changes how selected rules behave once its conditions match.
Use the `on_match` field to express the desired outcome:

| Value | Effect |
| --- | --- |
| `bypass` (default) | Skip rule evaluation entirely. No event is produced. |
| `monitor` | Evaluate the rule but force the verdict to monitoring and set the action to the built-in `monitor` action. |
| `<custom action>` | Run the rule normally and override any produced action with the provided string. |

Rule exclusions ignore the `inputs` field and do not remove data from the
request. They are best suited for turning off noisy rules, forcing monitoring
mode for specific traffic, or routing matches to a custom action.

### Example

```json
{
  "id": "skip-log4shell-on-backend",
  "conditions": [
    { "operator": "match_regex", "parameters": { "inputs": [ { "value": { "address": "server.address" } } ], "regex": "^10\\." } }
  ],
  "rules_target": [
    { "rule_id": "log4shell" }
  ],
  "on_match": "bypass"
}
```

This exclusion disables the `log4shell` rule whenever the server address starts
with `10.`.

## Input exclusions

Input exclusions keep the rule active while hiding specific request fields. Use
them when a rule should ignore known benign parameters or payload sections.

Additional fields:

| Field | Type | Required | Description |
| --- | --- | --- | --- |
| `inputs` | array | yes | List of addresses and optional key paths pointing to values that should be removed from rule evaluation. |

Each entry inside `inputs` must contain:

- `address` (string, required): data collection to inspect. Examples include
  `server.request.query`, `server.request.body`, or any address recognised by
  the ruleset.
- `key_path` (array of strings, optional): navigates into nested structures.
  Leave empty to ignore the entire address. Use `"*"` to match any key at that
  depth. Omitted keys (such as array indices) are treated as wildcards.

When the optional `conditions` array evaluates to `true`, all matching values
described by `inputs` are removed for the targeted rules. Other rules continue
to see the original data.

### Example

```json
{
  "id": "ignore-debug-parameter",
  "inputs": [
    {
      "address": "server.request.query",
      "key_path": ["debug"]
    }
  ],
  "rules_target": [
    { "tags": { "type": "security_scanner" } }
  ]
}
```

Here, any rule tagged with `type=security_scanner` ignores the `debug` query
parameter. The exclusion applies unconditionally because no `conditions` field
is provided.

## When exclusions are evaluated

- Configuration loading enforces unique `id` values and drops exclusions whose
  version constraints do not match the running library.
- During request processing libddwaf evaluates exclusion conditions before each
  rule. The first successful match is memoised for the rest of the request,
  keeping filters fast even when multiple rules reference them.
- Rule exclusions determine the final verdict (`bypass`, `monitor`, or custom
  action). Input exclusions prune fields and let the rule produce a normal
  result using the reduced data.

Use exclusions sparingly and document their intent. They provide fine-grained
control over rule behaviour, but overly broad entries can hide important
signals. Start with specific targets and conditions, monitor the effect, and
expand only when necessary.
