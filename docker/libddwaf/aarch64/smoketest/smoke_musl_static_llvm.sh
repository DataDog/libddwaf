#!/bin/bash -e

set -x
mkdir -p musl_static_llvm
cd musl_static_llvm
cmake -DCMAKE_TOOLCHAIN_FILE=../../Toolchain.cmake \
  -DCMAKE_SYSROOT=/muslsysroot \
  -DCMAKE_EXE_LINKER_FLAGS="-v -fuse-ld=lld" \
  -DCMAKE_PREFIX_PATH=/muslsysroot/share/cmake/libddwaf \
  -DLIBDDWAF_SMOKE_LINK_STATIC=ON \
  -DLIBDDWAF_SMOKE_LINK_STATIC_FLAGS="-Wl,--push-state -Wl,-L/muslsysroot/lib -l:libc++.a -l:libc++experimental.a -l:libc++abi.a -l:libunwind.a -Wl,--pop-state" \
  ../../../../../smoketest/
make
