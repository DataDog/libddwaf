# Scanners

Scanners provide optional annotations and filtering for processors that inspect structured data. They are primarily used by the `extract_schema` processor to tag or prune parts of a generated schema based on predefined logic.

## Where scanners are used

- **`extract_schema`**: accepts a `parameters.scanners` list of includes/excludes by ID or tags. The resolved set of scanner implementations is passed to the processor to influence how fields are marked or trimmed in the generated schema maps (`{address}.schema`).

No other built-in processors currently consume scanners, but the mechanism is extensible for new generators.

## Selection rules

When resolving the scanner set, references are applied in this precedence order (`src/processor/extract_schema.*`):

1. Exclusions by ID.
2. Inclusions by ID.
3. Exclusions by tags.
4. Inclusions by tags.

This ordering ensures explicit IDs win over tag-based selectors, and exclusions win over inclusions.

## Configuration shape

Within a processor definition:

```json
{
  "id": "schema-extractor",
  "generator": "extract_schema",
  "parameters": {
    "scanners": {
      "include": ["trusted-scanner-id"],
      "exclude": [{ "tags": ["experimental"] }]
    },
    "mappings": [
      { "inputs": [{ "address": "server.request.body" }], "output": "server.request.body.schema" }
    ]
  },
  "evaluate": true
}
```

- `include` / `exclude` accept a mix of IDs (strings) and tag selectors (`{ "tags": [...] }`).
- If neither include nor exclude is provided, all scanners are available to the processor.

## Runtime behaviour

Each selected scanner can:

- Annotate schema nodes (for example mark sensitive fields).
- Suppress nodes that match pruning criteria.
- Leave the node untouched.

The processor applies scanners to every visited node during schema extraction, respecting the include/exclude set resolved at configuration load time.
