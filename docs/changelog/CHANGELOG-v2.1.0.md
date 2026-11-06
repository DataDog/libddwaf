# v2.1.0

## Release Changelog

### Changes

- Add large array and map representations ([#511](https://github.com/DataDog/libddwaf/pull/511)).
- Add support for transformers on RASP operators ([#506](https://github.com/DataDog/libddwaf/pull/506)).
- Add lower_equal and greater_equal operator aliases ([#507](https://github.com/DataDog/libddwaf/pull/507)).

### Fixes

- Improvements on RASP operator transformer support ([#508](https://github.com/DataDog/libddwaf/pull/508)).
- Avoid using __builtin_cpu_supports ([#505](https://github.com/DataDog/libddwaf/pull/505)).

### Miscellaneous

- Use new images to build binaries (upgrade to Clang 21.1; link to libm now needed)
- Drop support for i386 and armv7
- Upload ELF debug symbols on release ([#509](https://github.com/DataDog/libddwaf/pull/509)).
- Publish source as [crate](https://crates.io/crates/libddwaf-src)
  ([#514](https://github.com/DataDog/libddwaf/pull/514),
  [#516](https://github.com/DataDog/libddwaf/pull/516)).
