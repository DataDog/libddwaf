# Upgrading libddwaf

The C API in libddwaf v2 has experienced a large number of changes, primarily around the creation and use of ddwaf_object. This guide aims to provide an overview of the changes required to upgrade from v1.x to v2.x, however it is recommended that the reader carefully reads the [C API Reference](c-api/api.md) and [ddwaf.h](../../include/ddwaf.h).

## Summary
- Allocators have been introduced to all relevant API functions.
- The layout of `ddwaf_object` has dramatically changed to reduce the amount of memory required for a single object, which now only requires 16 bytes.
- Two new string types have been introduced:
  - Small string: a string of 14 bytes or less, stored within the object memory itself without extra allocations.
  - Literal string: a c-string which should be treated as read-only and never freed.
- Object creation and access functions have been changed significantly, primarily to avoid the need for intermediate objects.
- `ddwaf_run` has been renamed to `ddwaf_context_eval`.
- Subcontexts have been introduced to replace ephemerals, their lifecycle and use is equivalent to that of the context.
- `ddwaf_config` has been removed:
  - Evaluation limits have been entirely removed, the caller must now enforce any relevant limits during serialisation.
  - Obfuscator regexes must now be provided through configuration: `{obfuscator: {key_regex: <value>, value_regex: <value>}}`.
  - The free function is no longer needed due to the introduction of allocators.

## Note on Allocators
The ownership of any allocated memory crossing the API boundary was one of the pain points of libddwaf v1. To fix this, v2 introduces allocators, which can be used to define the explicit ownership of the allocated memory.

Since the use of allocators is now required on many of the API functions, the migration examples will use the default allocator and will also include allocator destruction for illustrative purposes, as the destruction of the default allocator is a no-op.

See the [allocators document](../allocators.md) for more information on the different types of allocators available.

## 1. WAF instantiation: Removal of `ddwaf_config`

The main changes pertaining to WAF initialisation is the removal of `ddwaf_config`, as the evaluation limits have been entirely removed in favour of user-controlled truncation and the free function is no longer required due to the explicit memory ownership defined through allocators. As a consequence, instantiation through `ddwaf_init` has changed as follows:

**v1.x:**
```c
ddwaf_object ruleset = ...;
ddwaf_config config = ...;

ddwaf_object diagnostics;
ddwaf_handle handle = ddwaf_init(&ruleset, &config, &diagnostics);
```

**v2.x:**
```c
ddwaf_object ruleset = ...;

ddwaf_object diagnostics;
ddwaf_handle handle = ddwaf_init(&ruleset, &diagnostics);
```

When instantiating through the builder, the deprecation of `ddwaf_config` only affects `ddwaf_builder_init`:
**v1.x:**
```c
ddwaf_config config = ...;
ddwaf_builder builder = ddwaf_builder_init(&config);
```

**v2.x:**
```c
ddwaf_builder builder = ddwaf_builder_init();
```

## 2. WAF Context: Input & Output Allocators and Removal of Ephemerals


## 3. WAF Subcontext: Replacement of Ephemerals

## 4. Object Creation: New API & Allocator support


