# Actions Catalogue

Actions describe what the host should do when a rule matches. They are defined in the optional top-level `actions` array of a configuration and are referenced by rules via their `on_match` field.

## Action schema

Each entry in `actions` uses this shape:

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `id` | string | yes | Identifier referenced by `on_match`. Must be unique across the document. |
| `type` | string | yes | One of `block_request`, `redirect_request`, `monitor`, `generate_stack`, `generate_schema`, or a custom type understood by the host application. |
| `parameters` | object | yes | Free-form parameters passed through to the action mapper and on to the host/caller. |

## Built-in defaults

libddwaf always exposes a baseline catalogue, even if the `actions` array is omitted:

- `block` (alias of `block_request`) with defaults: `status_code=403`, `grpc_status_code=10`, `type=auto`.
- `monitor` (no parameters).
- `stack_trace` (`generate_stack`).
- `extract_schema` (`generate_schema`).

You can override these by redefining their IDs in `actions`, or add new entries for custom behaviour.

## Action types

### `block_request`

Signals that the request should be blocked. Parameters:

- `status_code` (optional): HTTP status to emit; any 3-digit code is accepted. Defaults to `403` if missing or invalid.
- `grpc_status_code` (optional): gRPC status (unsigned) to emit; defaults to `10` if missing or invalid.
- `type` (optional): transport hint (for example `auto`).

Missing parameters are populated from the built-in `block` defaults. Reserved parameters `security_response_id` and `stack_id` are stripped.

### `redirect_request`

Instructs the caller to respond with an HTTP redirect. Parameters:

- `location` (string, required): absolute or root-anchored URL to redirect to.
- `status_code` (optional): one of `301`, `302`, `303`, or `307`. Defaults to `303` if absent or invalid.

The parser validates the URL scheme (`http`/`https`) and ensures relative redirects start with `/`. When validation fails, the action is replaced by the default `block_request`. Reserved parameters `security_response_id` and `stack_id` are stripped.

### `monitor`

Instructs the caller to log/monitor without blocking. Parameters: none. Always emits the `monitor` action ID. Reserved parameters are stripped.

### `generate_stack`

Requests a stack trace capture. Parameters:

- `stack_id` (string, optional): identifier for the captured stack. Other parameters are ignored. Reserved parameters are stripped.

### `generate_schema`

Requests schema generation for the current request data. Parameters: none; any provided values are passed through to the host. Reserved parameters are stripped.
