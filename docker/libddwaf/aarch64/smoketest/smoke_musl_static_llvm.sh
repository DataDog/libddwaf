#!/bin/bash -e

set -x
mkdir -p musl_static_llvm
cd musl_static_llvm
cmake -DCMAKE_TOOLCHAIN_FILE=../../Toolchain.cmake \
  -DCMAKE_SYSROOT=/muslsysroot \
  -DCMAKE_EXE_LINKER_FLAGS="-v -fuse-ld=lld" \
  -DCMAKE_PREFIX_PATH=/muslsysroot/share/cmake/libddwaf \
  -DLINK_DDWAF_STATIC=ON \
  ../../../../../smoketest/
make
