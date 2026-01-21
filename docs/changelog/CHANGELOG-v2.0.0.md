# v2.0.0-alpha0

libddwaf v2.0.0 represents a significant redesign of the C API, focusing on explicit memory ownership, reduced memory footprint, and a more consistent interface. Beyond the public API, the internals have also been refactored to use safer and more C++-native abstractions. This is an alpha release intended for early adopters and binding library maintainers to begin integration work.

As expected, this release is not backwards compatible; the upgrading guide at `docs/upgrading/UPGRADING-v2.0.md` provides detailed migration examples for each of the breaking changes.

### Memory Ownership and Allocators

The most fundamental change in v2 is the introduction of allocators throughout the API. In v1, memory ownership across the API boundary was often ambiguous, leading to potential issues in complex integration scenarios. The new allocator system makes memory ownership explicit: callers provide an allocator when creating objects and use the same allocator when destroying them. A default allocator is available via `ddwaf_get_default_allocator()` for simple use cases, while custom allocators enable advanced memory management strategies.

### Object Model and Creation API

The `ddwaf_object` structure has been completely redesigned to reduce memory overhead. A single object now requires only 16 bytes, down from a considerably larger footprint in v1. This was achieved through carefully redesigning each of the possible type variants and, more specifically, through the removal of map keys from the main `ddwaf_object` in favour of representing maps through a separate `ddwaf_object_kv` structure. Indirectly, this new version enables further reduction in the memory and allocations through the introduction of small strings, where strings of 14 bytes or fewer are stored directly within the object without additional heap allocation, and literal strings, which reference read-only memory that is never freed by the library.

Object creation functions have been renamed to follow a consistent `ddwaf_object_set_*` pattern and now require an allocator parameter where allocation may occur. Container insertion returns a pointer to the newly inserted element, eliminating the need for intermediate objects. For example, where v1 required creating a value object separately and then adding it to a map, v2 allows direct initialisation: `ddwaf_object_set_string(ddwaf_object_insert_key(&map, "key", 3, alloc), "value", 5, alloc)`. This pattern reduces boilerplate and makes the ownership model clearer.

### Context and Subcontext Lifecycle

The function `ddwaf_run` has been renamed to `ddwaf_context_eval` for consistency with the rest of the API. More significantly, ephemeral data semantics have been replaced with a new subcontext mechanism. In v1, ephemeral data was passed as a separate parameter to each `ddwaf_run` call and was not retained. In v2, a subcontext is explicitly created from a parent context via `ddwaf_subcontext_init`, evaluated with `ddwaf_subcontext_eval`, and destroyed with `ddwaf_subcontext_destroy`. Subcontexts inherit all data from their parent context but maintain their own isolated evaluation state. Multiple concurrent subcontexts can be created from the same parent context, each defining its own data scope and lifetime.

## Release Changelog
### Changes

- Object model overhaul: immutable `object_view`, owned/borrowed writable objects, raw configuration on `object_view`, container view types, and updated unit tests ([#341](https://github.com/DataDog/libddwaf/pull/341), [#378](https://github.com/DataDog/libddwaf/pull/378), [#382](https://github.com/DataDog/libddwaf/pull/382), [#387](https://github.com/DataDog/libddwaf/pull/387), [#390](https://github.com/DataDog/libddwaf/pull/390), [#391](https://github.com/DataDog/libddwaf/pull/391), [#394](https://github.com/DataDog/libddwaf/pull/394), [#408](https://github.com/DataDog/libddwaf/pull/408), [#413](https://github.com/DataDog/libddwaf/pull/413)), ([#476](https://github.com/DataDog/libddwaf/pull/476)).
- Allocator API: propagate allocators through contexts/subcontexts, expose allocator-aware interfaces, and stop generating zero-terminated strings ([#418](https://github.com/DataDog/libddwaf/pull/418), [#420](https://github.com/DataDog/libddwaf/pull/420), [#427](https://github.com/DataDog/libddwaf/pull/427), [#452](https://github.com/DataDog/libddwaf/pull/452)).
- Refactored evaluation lifecycle: separated data insertion from evaluation and lifted evaluation stages out of the context ([#407](https://github.com/DataDog/libddwaf/pull/407), [#442](https://github.com/DataDog/libddwaf/pull/442)).
- Subcontexts with user-defined lifetimes and validator support for subcontexts/attributes ([#443](https://github.com/DataDog/libddwaf/pull/443), [#451](https://github.com/DataDog/libddwaf/pull/451)), ([#468](https://github.com/DataDog/libddwaf/pull/468)).
- Array indexing on key paths ([#458](https://github.com/DataDog/libddwaf/pull/458)).
- Instantiate obfuscator through configuration and remove `ddwaf_config` ([#464](https://github.com/DataDog/libddwaf/pull/464)).
- Return `DDWAF_MATCH` when events, attributes, or actions are present ([#455](https://github.com/DataDog/libddwaf/pull/455)).
- Remove legacy configuration schema (v1) support ([#482](https://github.com/DataDog/libddwaf/pull/482)).

### Fixes

- Report input attribute addresses on `ddwaf_known_addresses` ([#485](https://github.com/DataDog/libddwaf/pull/485)).
- Remove default allocator arguments ([#486](https://github.com/DataDog/libddwaf/pull/486)).

### Miscellaneous

- Upgrade fmt dependency and use as header-only ([#478](https://github.com/DataDog/libddwaf/pull/478)).
- Increase macOS target to 14.2.1 ([#477](https://github.com/DataDog/libddwaf/pull/477)).
- Add option to build on valgrind to avoid RE2 UB noise ([#480](https://github.com/DataDog/libddwaf/pull/480)).
- Lint all headers and add tests ([#474](https://github.com/DataDog/libddwaf/pull/474)).
- Intertwine context and subcontext calls within benchmark ([#469](https://github.com/DataDog/libddwaf/pull/469)).
- Disable unreliable GCC / Clang benchmarks ([#470](https://github.com/DataDog/libddwaf/pull/470)).
- Upload coverage reports to Datadog ([#471](https://github.com/DataDog/libddwaf/pull/471)).
- Remove mingw builds ([#381](https://github.com/DataDog/libddwaf/pull/381)).
- Cleanup exclusion namespace and redundant references ([#456](https://github.com/DataDog/libddwaf/pull/456)).
- Expanded fingerprint and object-view tests ([#414](https://github.com/DataDog/libddwaf/pull/414)).
- Add fuzzer v2 ([#465](https://github.com/DataDog/libddwaf/pull/465)).
- Update logger to avoid dependencies on `ddwaf.h` ([#453](https://github.com/DataDog/libddwaf/pull/453)).
- Achieve 100% test coverage for src/utils.cpp ([#481](https://github.com/DataDog/libddwaf/pull/481)).
- Documentation ([#487](https://github.com/DataDog/libddwaf/pull/487)).
