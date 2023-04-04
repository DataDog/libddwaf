[![Build](https://github.com/DataDog/libddwaf/actions/workflows/build.yml/badge.svg)](https://github.com/DataDog/libddwaf/actions/workflows/build.yml)

# Datadog's WAF

``libddwaf`` is Datadog's implementation of a Web Application Firewall (WAF) engine, with a goal of low performance and memory overhead, and embeddability in a wide variety of language runtimes through a C API.

## Versioning semantics

`libddwaf` follows [Semantic Versioning 2.0](https://semver.org/), with a slight twist.

`libddwaf` is a heir to `libsqreen`, the latter which was semantically versioned using `0.y.z`:

> Major version zero (0.y.z) is for initial development. Anything MAY change at any time. The public API SHOULD NOT be considered stable.

To mark the break between `libsqreen` and `libddwaf` (which involved a lot of renaming and changes), it was decided to bump the major version, but some time was needed still to stabilise the public API. Therefore `libddwaf`'s `1.y.z` is operating following semver's usual `0.y.z`, with minor `y` meaning "breaking change" and patch `z` meaning "bugfix".

In addition `libddwaf`'s "unstable" marker on releases means the API may evolve and have breaking changes on minor versions. Nonetheless its codebase and resulting binaries are considered production-ready as the "unstable" marker only applies to `libddwaf`'s public API.

Since `libddwaf` should not be used directly and is wrapped by binding libraries to various languages, any such low-level C API change is handled by Datadog internally and isolated by the higher level binding code, which aims to provide a much stabler high level language-oriented API. In any case, the binding library dependency is directly consumed by the Datadog tracing client libraries, and should there be a breaking change in the binding API it would be handled as gracefully as technically possible within the tracing client library level, and properly handled using the tracing client library dependency verssion constraints so that it picks only compatible versions of the binding library.

## Building

### Quick Start

This project is built using `cmake`.

On Linux and Darwin, the following should produce a static and a dynamic library inside of `build`:

```
mkdir -p build && cd build
cmake ..
make -j4
```

A cross-platform way to achieve the same result (e.g on Windows):

```
cmake -E make_directory build
cd build
cmake ..
cmake --build . --target all -j4
```

And a more involved example, with specific targets, building, then running the test suite along with debug information:

```
cmake -E make_directory build packages
cd build
cmake -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_INSTALL_PREFIX=.. -DCPACK_PACKAGE_DIRECTORY=../packages ..
cmake --build . --config RelWithDebInfo --verbose --target libddwaf_shared --target libddwaf_static  --target testPowerWAF -j
cd ../tests
../build/tests/testPowerWAF
```

## Usage
