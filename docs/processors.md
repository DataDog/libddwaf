# Processor Reference

Processors are reusable building blocks that derive new addresses from existing request data. They can run before rule evaluation to enrich the object store (preprocessors) or after evaluation to attach additional attributes to the result payload (postprocessors). Each processor definition lives in the `processors` section of a configuration document and is parsed by `configuration/processor_parser.cpp`.

---

## Lifecycle and execution

- **Expression gate:** every processor carries a simplified expression (`conditions`) evaluated against the current context. If the expression returns `false` the processor is skipped for that evaluation.
- **Mappings:** for every entry under `parameters.mappings`, the engine resolves the addresses declared in the mapping according to the processor’s `param_names`. Key paths are supported but each parameter currently accepts a single address.
- **Evaluate flag:** when `evaluate: true`, the generated object is inserted into the context’s object store. Downstream rules can immediately consume the derived address.
- **Output flag:** when `output: true`, the generated object is added to the attribute collector so that it surfaces in the `attributes` map returned by `ddwaf_context_eval`.
- **Caching:** `processor_cache` keeps track of outputs that were already produced during the same evaluation (`generated`), optional arguments that have already been resolved (`evaluated`), and processor-specific state (for example fingerprint fragments). This prevents duplicate work when the same context is evaluated repeatedly.
- **Memory ownership:** preprocessors that feed rule evaluation clone their result into the user-provided allocator before returning it to the caller; otherwise results are stored directly in the default allocator.

A processor configured with `evaluate: true, output: false` behaves like a classic preprocessor. A processor with `evaluate: false, output: true` acts as a pure postprocessor. Many rule packs use `waf.context.processor` to gate expensive postprocessors so that agents can opt-in address by address.

---

## Configuration fields

Each entry in the `processors` array supports:

| Field | Description |
| --- | --- |
| `id` | Unique identifier for the processor definition. |
| `generator` | The processor type (see the list below). |
| `conditions` | Optional simplified expression that must evaluate to `true` before the processor runs. |
| `parameters.mappings` | Array of mappings. Every mapping defines the required inputs (per `param_names`) and an `output` address. |
| `parameters.scanners` | Optional include/exclude list of scanners (only used by `extract_schema`). |
| `min_version` / `max_version` | Optional semantic-version bounds for libddwaf compatibility. |
| `evaluate` | Boolean, defaults to `true`. Controls whether the output is inserted into the object store. |
| `output` | Boolean, defaults to `false`. Controls whether the output is exported via the attribute collector. |

If neither `evaluate` nor `output` is set, the processor is rejected during parsing.

---

## Scanners

`extract_schema` can depend on scanners (see `src/scanner.hpp`) to annotate or filter parts of the generated schema. Scanners can be referenced by ID or by tags. The builder resolves references with the following precedence:

1. Exclusions by ID (apply to everything).
2. Inclusions by ID.
3. Exclusions by tags.
4. Inclusions by tags.

The resulting set of `scanner*` pointers is passed to the processor instance.

---

## Supported generators

### `extract_schema`
- **Inputs:** `inputs` (variadic). Each mapping typically targets a request container such as `server.request.body`.
- **Usage:** Commonly configured with `evaluate: true` to materialise `{address}.schema` maps consumed by rules; optional `output: true` exposes the schema in WAF results.
- **Behaviour:** Walks complex objects up to a bounded depth (`max_container_depth`), summarises value types (null, boolean, integer, real, string), and records array shapes. The result is a compact JSON-like structure (see integration tests for examples). Scanners can tag or prune fields based on custom logic.

### `jwt_decode`
- **Inputs:** `inputs` (single address), often pointing to `server.request.headers.no_cookies["authorization"]`.
- **Usage:**  
  - `evaluate: true, output: false` (preprocessor) populates `server.request.jwt` so rules can inspect JWT header/payload claims.  
  - `evaluate: false, output: true` (postprocessor) exports the decoded token in results.
- **Behaviour:** Looks for `"Bearer "` prefixes, splits the token into header/payload/signature segments, base64url-decodes header and payload, and emits a map such as:  
  `{"header": {...}, "payload": {...}, "signature": {"available": true}}`.

### `uri_parse`
- **Inputs:** `inputs` (single string address, for example `server.request.uri.raw`).
- **Usage:** Usually configured as a postprocessor (`evaluate: false, output: true`) to expose structured URI data. With `evaluate: true` it can populate derived addresses for rules.
- **Behaviour:** Parses the URI into scheme, user info, host, port, path, fragment, and a map of query parameters where repeated keys are promoted to arrays. Outputs a map with keys `scheme`, `userinfo`, `host`, `port`, `path`, `query`, and `fragment`.

### Fingerprint processors

These generators emit deterministic strings (fragments) prefixed with the fingerprint family. The fragments follow the `<prefix>-<normalized components…>` convention.

- **`http_endpoint_fingerprint`**  
  - **Inputs:** `method`, `uri_raw`, optional `query`, optional `body`.  
  - **Output address:** `_dd.appsec.fp.http.endpoint`.  
  - **Behaviour:** Normalises the method, strips queries from the raw URI, hashes selected parameters, and caches fragments per context to avoid recomputation when optional inputs arrive late.

- **`http_header_fingerprint`**  
  - **Inputs:** `headers` (map).  
  - **Output address:** `_dd.appsec.fp.http.header`.  
  - **Behaviour:** Records which well-known headers are present, normalises unknown headers, and includes a lowercase hash of the User-Agent.

- **`http_network_fingerprint`**  
  - **Inputs:** `headers` (map).  
  - **Output address:** `_dd.appsec.fp.http.network`.  
  - **Behaviour:** Tracks which forwarding headers carry client IP information and counts comma-separated IPs in the highest precedence header.

- **`session_fingerprint`**  
  - **Inputs:** optional `cookies`, optional `session_id`, optional `user_id`.  
  - **Output address:** `_dd.appsec.fp.session`.  
  - **Behaviour:** Hashes user/session identifiers and the cookie map to build a session fingerprint. Optional inputs trigger re-evaluation only when new data appears thanks to `processor_cache.evaluated`.

Fingerprints are usually configured as postprocessors (`evaluate: false, output: true`) and gated by the `waf.context.processor["fingerprint"]` address.

---

## Practical tips

- **Opt-in toggles:** use `waf.context.processor` flags in rule packs so agents can enable expensive processors selectively.
- **Key paths:** mappings accept `key_path`, but the current parser only consumes the first address per parameter. If you need multiple inputs, define multiple mappings targeting different outputs.
- **Preprocessor vs postprocessor:** remember that preprocessors mutate the context store. Postprocessors never affect rule evaluation—only the result payload.
- **Timeouts:** processors honour the evaluation deadline; long-running logic should handle `ddwaf::timeout_exception`.

Refer to `tests/integration/processors/*` for concrete configuration examples and expected outputs.
