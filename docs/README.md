# Documentation Index

The documents below describe libddwaf’s public API and internal primitives. Use them as entry points when integrating or upgrading the engine.

- [Overview](overview.md) – Architectural summary and execution pipeline.
- [Evaluation](evaluation.md) – Runtime ordering of processors, filters, modules, and WAF collections.
- Primitives:
    - [Rules](rules.md) – Schema, metadata, and placement of `rules` and `custom_rules` entries in configuration payloads.
    - [Processors](processors.md) – Built-in preprocessors/postprocessors and configuration options.
    - [Exclusion Filters](exclusions.md) – Configure rule and input exclusions in configurations.
    - [Actions](actions.md) – Top-level action catalogue referenced by rules.
    - [Scanners](scanners.md) – Include/exclude controls used by processors such as `extract_schema`.
    - [Conditions](conditions.md) – Shared expression syntax used by rules, processors, and exclusions.
    - [Addresses](addresses.md) – List of supported and / or commonly used addresses and their expected value types.
    - [Operators](operators.md) – Scalar and detector operators with parameters and version notes.
    - [Transformers](transformers.md) – Input transformation utilities available to rules.
- [C API Reference](c-api/api.md) – Comprehensive description of all exported functions, structs, and macros.
- [Binding Integration Guide](c-api/binding-integration-guide.md) – Guidance for language bindings embedding libddwaf.
- [Latest Changelog](changelog/CHANGELOG-latest.md) – Release notes for the current major version; see `docs/changelog/` for history.

For migration guidance, start with [Upgrading to 2.0](upgrading/UPGRADING-v2.0.md) or consult the versioned guides in [`docs/upgrading/`](upgrading/).
