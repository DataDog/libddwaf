# Actions Catalogue

Actions describe what the host should do when a rule matches. They are defined in the optional top-level `actions` array of a configuration document and are referenced by rules via their `on_match` field.

## Action schema

Each entry in `actions` uses this shape:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | string | yes | Identifier referenced by `on_match`. Must be unique across the document. |
| `type` | string | yes | One of `block_request`, `redirect_request`, `monitor`, `generate_stack`, `generate_schema`, or a custom type understood by the host application. |
| `parameters` | object | yes | Free-form parameters passed through to the action mapper. |

## Built-in defaults

libddwaf always exposes a baseline catalogue, even if the `actions` array is omitted:

- `block` (alias of `block_request`) with defaults: `status_code=403`, `grpc_status_code=10`, `type=auto`.
- `monitor` (no parameters).
- `stack_trace` (`generate_stack`).
- `extract_schema` (`generate_schema`).

You can override these by redefining their IDs in `actions`, or add new entries for custom behaviour.

## Validation rules

- `block_request` accepts `status_code`, `grpc_status_code`, and `type` (transport hint). Missing fields are filled from the default block action.
- `redirect_request` requires a non-empty `location` URL and an HTTP status code in `{301,302,303,307}` (default 303). Invalid redirects are downgraded to `block_request`.
- Reserved parameters `security_response_id` and `stack_id` are stripped for safety.

All other types are passed through as-is; the host integration is responsible for interpreting custom action types.
