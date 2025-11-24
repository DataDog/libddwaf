# Condition Schema

Conditions are the common building block used by rules, processors, and exclusion filters. Each component embeds a `conditions` array that forms a logical expression evaluated against the current request data. The parser for these expressions lives in `src/configuration/common/expression_parser.cpp` and is shared across configuration types.

## Expression semantics

- The `conditions` array represents a conjunction: entries are evaluated in order until one fails; if all succeed the expression is `true`. An empty array implicitly evaluates to `true`.
- Results are cached per context. Once a condition has matched a given object, subsequent evaluations in the same request skip the work unless new input appears.
- All operators documented in the [Operator Reference](operators.md) are valid inside any expression. Processor and exclusion expressions are parsed with the same rules as rule expressions.

## Condition object

Every element in the `conditions` array has the same top-level shape:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `operator` | string | yes | Name of the matcher to run (for example `match_regex`, `phrase_match`, `exists`). Operators that carry a schema version use the `name@vN` suffix (for example `ssrf_detector@v1`). |
| `parameters` | object | yes | Operator-specific parameters plus the argument mappings (see below). |

The exact keys inside `parameters` depend on the operator. Scalar matchers such as `equals`, `match_regex`, `ip_match`, `phrase_match`, `greater_than`, and `lower_than` require a `value` and `type` (or a `regex`/`list`/`data` depending on the matcher) in addition to their inputs. Complex detectors such as `ssrf_detector` also accept `options` and `policy` blocks. Refer to the operator documentation for the full list of supported keys per matcher.

## Mapping inputs to a condition

Most operators accept an `inputs` argument under `parameters`. Each entry in `inputs` maps one address from the request (or derived data) into the operator:

| Key | Type | Required | Description |
| --- | --- | --- | --- |
| `address` | string | yes | The address to inspect, such as `server.request.query`, `server.request.body`, or `_dd.appsec.fp.http.endpoint`. |
| `key_path` | array of string/int | no | Optional navigation into nested maps or arrays. Strings address map keys; integers address array indices. Use `"*"` as a wildcard segment. |
| `transformers` | array of strings | no | Overrides the transformer chain for this input. At most 10 entries. When omitted, the expression-level transformers (rule-level) apply. |

Inputs are ordered; non-variadic operators accept exactly one entry while variadic ones consume every entry in the list. The accepted argument names (`inputs`, `value`, etc.) come from the operator signature; for example the `exists` operator only accepts `inputs` while structured detectors may name their arguments differently.

### Data source and transformers

- By default expressions read **values** from each address. If a rule-level `transformers` array includes the sentinel `keys_only`, the condition walks map keys instead. The sentinel `values_only` restores the default. These sentinels are ignored for processors and exclusions because they do not carry a rule-level transformer list.
- Per-input `transformers` replace the rule-level chain for that target and always operate on values. When present, the data source for that input is forced back to values even if `keys_only` was declared at the rule level.
- Transformer identifiers are listed in the [Transformer Reference](transformers.md).

## Putting it together

Rule, processor, and exclusion configurations all embed conditions using the schema above. Examples:

- **Rule condition** that matches a numeric status code:  
  ```json
  {
    "operator": "equals",
    "parameters": {
      "inputs": [{ "address": "server.response.status" }],
      "type": "unsigned",
      "value": 403
    }
  }
  ```
- **Processor gate** controlled by a context flag:  
  ```json
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
  ```
- **Exclusion filter** applied when the request path contains `/health`:  
  ```json
  {
    "operator": "match_regex",
    "parameters": {
      "inputs": [
        { "address": "server.request.uri.raw", "transformers": ["lowercase"] }
      ],
      "regex": "/health(/|$)"
    }
  }
  ```

Whichever component owns the `conditions` array determines how the expression is used—rules treat it as the match logic for detection, processors as an execution gate, and exclusions as the predicate for muting or pruning. The underlying schema and evaluation semantics remain the same.
