# Processors

Processors are reusable transformations that derive new addresses from request data. They can run before rule evaluation (preprocessors) or after rule evaluation to enrich result attributes (postprocessors). Each processor lives in the `processors` array of a configuration document.

## Processor schema

Required fields:

| Field | Type | Description |
| --- | --- | --- |
| `id` | string | Unique identifier for diagnostics and overrides. |
| `generator` | string | Processor type (for example `uri_parse`, `jwt_decode`, `extract_schema`, fingerprint generators). |

Optional fields:

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `conditions` | array | `[]` | Simplified expression that must evaluate to `true` before the processor runs. See [conditions](common/conditions.md). |
| `parameters.mappings` | array | `[]` | Input/output bindings; see below. |
| `parameters.scanners` | array | `[]` | Scanner include/exclude filters (only for `extract_schema`). |
| `min_version`, `max_version` | semantic version | unrestricted | Restrict the processor to specific libddwaf versions. |
| `evaluate` | boolean | `true` | When `true`, output is inserted into the object store (preprocessor). |
| `output` | boolean | `false` | When `true`, output is exported via the attribute collector (postprocessor). |

At least one of `evaluate` or `output` must be `true`; otherwise the processor is rejected.

### Mappings

Each entry in `parameters.mappings` wires processor inputs to addresses and declares an output:

| Key | Type | Notes |
| --- | --- | --- |
| `<param>` | array | Required inputs keyed by the generator’s `param_names` (for example `inputs`, `headers`, `uri_raw`, `output`). Each array entry contains an `address` and optional `key_path`. |
| `output` | string | Address where the generated object will be stored/emitted. |

Inputs can provide `key_path` to navigate nested structures and may include only one address per parameter (current parser limitation).

### Lifecycle and caching

- **Preprocessors** (`evaluate: true`) run before exclusions and rules. Derived addresses are immediately available to conditions. Results are cloned into the caller allocator.
- **Postprocessors** (`output: true`) run after rule evaluation and append attributes to the result payload without affecting rule logic.
- Expressions, resolved inputs, and generated outputs are cached per context to avoid recomputation across evaluations. Optional parameters trigger re-evaluation only when new inputs appear.
- Processors honor the evaluation deadline and throw on timeout.

## Supported generators (summary)

- `extract_schema`: Walks complex objects to build `{address}.schema` summaries; can use scanners; often configured as both pre- and postprocessor.
- `jwt_decode`: Decodes JWT header/payload; commonly populates `server.request.jwt`.
- `uri_parse`: Breaks a URI into structured components and query map.
- Fingerprints: `http_endpoint_fingerprint`, `http_header_fingerprint`, `http_network_fingerprint`, `session_fingerprint`; emit deterministic fingerprint fragments under `_dd.appsec.fp.*`.

Refer to integration tests under `tests/integration/processors` for concrete payloads and expected outputs.

## Example configuration

```json
{
  "processors": [
    {
      "id": "fingerprint-http-endpoint",
      "generator": "http_endpoint_fingerprint",
      "conditions": [
        {
          "operator": "equals",
          "parameters": {
            "inputs": [
              { "address": "waf.context.processor", "key_path": ["fingerprint"] }
            ],
            "type": "boolean",
            "value": true
          }
        }
      ],
      "parameters": {
        "mappings": [
          {
            "method": [{ "address": "server.request.method" }],
            "uri_raw": [{ "address": "server.request.uri.raw" }],
            "query": [{ "address": "server.request.query" }],
            "body": [{ "address": "server.request.body" }],
            "output": "_dd.appsec.fp.http.endpoint"
          }
        ]
      },
      "evaluate": false,
      "output": true
    }
  ]
}
```

This example gates a postprocessor on a context flag, generates a deterministic endpoint fingerprint, and exports it as an attribute without affecting rule evaluation.
