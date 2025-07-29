#!/bin/bash

# FIXME: move me to a real Dockerfile

set -e

apt-get update && apt-get install -y \
    wget \
    gnupg \
    software-properties-common \
    && wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - \
    && echo 'deb http://apt.llvm.org/jammy/ llvm-toolchain-jammy-19 main' > /etc/apt/sources.list.d/llvm-toolchain.list \
    && apt-get update

apt-get install -y \
    build-essential \
    cmake \
    git \
    curl \
    python3 \
    python3-pip \
    llvm-19 \
    llvm-19-dev \
    clang-19 \
    lld-19 \
    libc++-19-dev \
    libc++abi-19-dev \
    ninja-build \
    libssl-dev \
    libcurl4-openssl-dev \
    zlib1g-dev \
    xxd \
    gdb

rm -rf /var/lib/apt/lists/*

update-alternatives --install /usr/bin/clang clang /usr/bin/clang-19 100
update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-19 100
update-alternatives --install /usr/bin/llvm-config llvm-config /usr/bin/llvm-config-19 100
update-alternatives --install /usr/bin/llvm-ar llvm-ar /usr/bin/llvm-ar-19 100
update-alternatives --install /usr/bin/llvm-ranlib llvm-ranlib /usr/bin/llvm-ranlib-19 100
update-alternatives --install /usr/bin/llvm-nm llvm-nm /usr/bin/llvm-nm-19 100
update-alternatives --install /usr/bin/llvm-objdump llvm-objdump /usr/bin/llvm-objdump-19 100
update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-19 100

cd /opt
git config --global --add safe.directory /workspace && git clone https://github.com/AFLplusplus/AFLplusplus.git
cd /opt/AFLplusplus

# Build AFL++ with LTO support
make clean
make -j$(nproc) all
make install

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


# Build individual AFL++ fuzzers
cd /workspace/fuzzer
mkdir -p build
cd build

echo "Building AFL++ fuzzers in $(pwd)..."
cmake .. \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_COMPILER=${CC} \
    -DCMAKE_CXX_COMPILER=${CXX} \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g" \
    -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -g"

echo "Building fuzzers with $(nproc) threads"

make -j$(nproc)

echo "AFL++ fuzzers built successfully!"
echo "Available fuzzers in $(pwd):"
ls -la *_fuzz