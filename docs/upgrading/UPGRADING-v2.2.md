# Upgrading libddwaf to v2.2.0

Version 2.2.0 is source and binary compatible with 2.1.x and requires no code
changes. The notes below describe behaviour changes that bindings may want to
be aware of.

## Rejected configuration updates are fully removed

When `ddwaf_builder_add_or_update_config` rejects a configuration, the path is
now always unregistered and anything collected from it is discarded.
Previously, a configuration that failed to load (e.g. with an unsupported or
malformed `version`, or invalid `metadata`) could remain listed by
`ddwaf_builder_get_config_paths` with no content behind it, and elements
loaded before a later section failed could remain in the active configuration.

Bindings that inspect `ddwaf_builder_get_config_paths` to decide whether to
restore their default ruleset will now see rejected paths disappear, as
expected. As before, a rejected update drops the previous configuration of
that path, unless the root is not a map, in which case nothing is touched.

Top-level parsing errors are now also reported in the `error` field of the
diagnostics object.

## String conversion on scalar operators

The `equals`, `greater_than` and `lower_than` operators, as well as their
negated forms (`!equals`, `lower_equal` and `greater_equal`), accept a new
`convert_strings` option. When enabled, string values are converted to the
type of the operator before being compared, which allows rules to evaluate
numeric or boolean values that arrive as strings:

```yaml
- operator: greater_than
  parameters:
    inputs:
      - address: server.request.query
        key_path: [page_size]
    type: unsigned
    value: 1000
    options:
      convert_strings: true
```

The option is disabled by default, so existing rules are unaffected. Strings
that can't be fully converted to the operator type are not evaluated, which
means negated operators don't match them either.

## Linux shared library no longer depends on libm

The released Linux shared library now bundles the libm functionality it
requires, so `libm.so` is no longer a runtime dependency. The static library
still requires libm, so it should remain on the link line.
