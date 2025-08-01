#!/bin/bash

# Build script for AFL++ libddwaf fuzzing

set -e

echo "Building libddwaf with AFL++ instrumentation..."

# Set AFL++ environment
export CC=afl-clang-lto
export CXX=afl-clang-lto++
export AFL_USE_ASAN=1
export AFL_USE_UBSAN=1

# Create build directory
mkdir -p /workspace/build
cd /workspace/build

# Configure with CMake
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=${CC} \
    -DCMAKE_CXX_COMPILER=${CXX} \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"

# Build the project
make -j$(nproc)

echo "Building AFL++ fuzzers..."

# Build individual AFL++ fuzzers
cd /workspace/fuzzer
mkdir -p build
cd build

cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=${CC} \
    -DCMAKE_CXX_COMPILER=${CXX} \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"

echo "Building fuzzers with $(nproc) threads"

make -j$(nproc)

echo "AFL++ fuzzers built successfully!"
echo "Available fuzzers:"
ls -la *_fuzz

echo ""
echo "To run in Docker:"
echo "docker run -v \$(pwd):/workspace -it libddwaf-afl" 
echo ""
echo "Then run a fuzzer (it should also run fine on a linux host):"
echo "afl-fuzz -i corpus_dir -o output_dir ./sha256_fuzz @@"