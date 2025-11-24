# Documentation Index

The documents below describe libddwaf’s public API and internal primitives. Use them as entry points when integrating or upgrading the engine.

- [Overview](overview.md) – Architectural summary and execution pipeline.
- [Address Reference](addresses.md) – List of supported ASM addresses and their expected value types.
- [Operator Reference](operators.md) – Scalar and detector operators with parameters and version notes.
- [Transformer Reference](transformers.md) – Input transformation utilities available to rules.
- [Processor Reference](processors.md) – Built-in preprocessors/postprocessors and configuration options.
- [Actions](actions.md) – Top-level action catalogue referenced by rules.
- [Rules Configuration](rules.md) – Schema, metadata, and placement of `rules` and `custom_rules` entries in configuration payloads.
- [Exclusion Filters](exclusions.md) – Configure rule and input exclusions in configurations.
- [Evaluation Flow](evaluation.md) – Runtime ordering of processors, filters, modules, and WAF collections.
- [C API Reference](c-api/api.md) – Comprehensive description of all exported functions, structs, and macros.

For migration guidance, start with [Upgrading to 2.0](upgrading/UPGRADING-v2.0.md) or consult the versioned guides in [`docs/upgrading/`](upgrading/).
