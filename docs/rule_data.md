# Rules Data

Rules data supplies external datasets consumed by operators such as `ip_match` and `exact_match`. It lives in the top-level `rules_data` map keyed by dataset identifier.

## Schema

`rules_data` is a map of entries:

| Key | Value type | Description |
| --- | --- | --- |
| `<data_id>` | array | List of values for the dataset (strings for regex/phrase data, IP/CIDR strings for `ip_match`, etc.). |

Datasets can be shared across base and custom rules as long as the `data` field in the rule’s operator points to the same `<data_id>`.

## Example

```json
{
  "rules_data": {
    "trusted-ips": [
      "10.0.0.0/8",
      "192.168.0.0/16"
    ],
    "blocked-usernames": [
      "admin",
      "root"
    ]
  }
}
```

A rule using `ip_match` may reference `"data": "trusted-ips"`; a rule using `exact_match` can reference `"data": "blocked-usernames"`.

## Diagnostics

During parsing, datasets are validated for type correctness per operator. Parsing diagnostics report missing datasets or invalid entries, and rules that reference invalid data are rejected.
