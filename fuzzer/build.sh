#!/bin/bash
set -eu

export CC=clang-19
export CXX=clang++-19

mkdir -p /workspace/build
cd /workspace/build

# Configure top-level project so fuzzer targets from fuzzer/CMakeLists.txt are available
cmake -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_BUILD_TYPE=RelWithDebInfo ..

# Build each fuzzer target declared as <dir>_fuzzer
for dir in /workspace/fuzzer/*/ ; do
    dir=${dir%/}
    base_dir=$(basename "$dir")
    if [[ "$base_dir" == "global" || "$base_dir" == "build" || "$base_dir" == "common" ]]; then
        continue
    fi
    echo "==> Building fuzzer target ${base_dir}_fuzzer"
    # The truncated_json target is new and must not silently fail to build;
    # older targets keep the tolerant behaviour until they can be verified.
    if [[ "$base_dir" == "truncated_json" ]]; then
        make -j $(nproc) ${base_dir}_fuzzer
    else
        make -j $(nproc) ${base_dir}_fuzzer || true
    fi
done

echo "✅ Finished building fuzzers"
