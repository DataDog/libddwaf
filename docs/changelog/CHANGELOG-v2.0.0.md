# v2.0.0-alpha0

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
