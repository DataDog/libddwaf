#!/bin/bash
set -eu

export CC=clang-17
export CXX=clang++-17

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
    make -j $(nproc) ${base_dir}_fuzzer || true
done

echo "✅ Finished building fuzzers"
