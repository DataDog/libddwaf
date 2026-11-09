# v2.2.0

## Release Changelog

### Changes

- Add option to convert strings on non-string matchers ([#510](https://github.com/DataDog/libddwaf/pull/510)).

### Fixes

- Clean up configuration state when an update is rejected ([#523](https://github.com/DataDog/libddwaf/pull/523)).
- Fix a false negative in the SSRF RASP operator ([#522](https://github.com/DataDog/libddwaf/pull/522)).
- Fix stack exhaustion on deeply nested JSON ([#521](https://github.com/DataDog/libddwaf/pull/521)).
- Fix UBSan errors; detect them in CI ([#519](https://github.com/DataDog/libddwaf/pull/519)).
- Add missing `ddwaf_object_set_string_nocopy` symbol to libddwaf.def ([#517](https://github.com/DataDog/libddwaf/pull/517)).

### Miscellaneous

- Update macOS runner due to the deprecation of the macos-14 runner ([#524](https://github.com/DataDog/libddwaf/pull/524)).
- Stop trusting compromised eMudhra roots in build and smoketest images ([#520](https://github.com/DataDog/libddwaf/pull/520)).
- Bundle libm symbols in release shared library ([#518](https://github.com/DataDog/libddwaf/pull/518)).
