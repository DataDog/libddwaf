# Processor Overrides

Processor overrides tweak processor definitions without redefining them. They live in the top-level `processor_overrides` array and currently control scanner selection for `extract_schema`.

## Schema

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `target` | array | yes | Identifies processors by `id` or `tags`. |
| `scanners.include` | array | no | Scanners to add (by `id` or `tags`). |
| `scanners.exclude` | array | no | Scanners to remove (by `id` or `tags`). |

At least one of `scanners.include` or `scanners.exclude` must be provided.

### Targets

Each entry in `target` accepts:

- `id`: processor identifier.
- `tags`: processor tags (all key/value pairs must match).

### Scanner merging

Overrides are incremental: includes add scanners, excludes remove scanners from the processor’s configured set. The resolution order matches scanner selection precedence:

1. Exclude by ID.
2. Include by ID.
3. Exclude by tags.
4. Include by tags.

Multiple overrides against the same processor are applied in sequence; later changes win when conflicting.

## Example

```json
{
  "processor_overrides": [
    {
      "target": [{ "id": "extract_schema_body" }],
      "scanners": {
        "include": [{ "id": "scanner-allowlist" }],
        "exclude": [{ "tags": { "type": "experimental" } }]
      }
    }
  ]
}
```
