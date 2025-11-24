# Documentation Index

The documents below describe libddwaf’s public API and internal primitives. Use them as entry points when integrating or upgrading the engine.

- [Overview](overview.md) – Architectural summary and execution pipeline.
- [Address Reference](addresses.md) – List of supported ASM addresses and their expected value types.
- [Operator Reference](configuration/common/operators.md) – Scalar and detector operators with parameters and version notes.
- [Transformer Reference](configuration/common/transformers.md) – Input transformation utilities available to rules.
- [Processor Reference](configuration/processors.md) – Built-in preprocessors/postprocessors and configuration options.
- [Actions](configuration/actions.md) – Top-level action catalogue referenced by rules.
- [Rules Configuration](configuration/rules.md) – Schema, metadata, and placement of `rules` and `custom_rules` entries in configuration payloads.
- [Exclusion Filters](configuration/exclusions.md) – Configure rule and input exclusions in configuration documents.
- [C API Reference](c-api/api.md) – Comprehensive description of all exported functions, structs, and macros.

For migration guidance, start with [Upgrading to 2.0](upgrading/UPGRADING-v2.0.md) or consult the versioned guides in [`docs/upgrading/`](upgrading/).
