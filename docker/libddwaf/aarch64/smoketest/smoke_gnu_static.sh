#!/bin/bash -e

set -x
mkdir -p gnu_static
cd gnu_static
cmake -DCMAKE_TOOLCHAIN_FILE=../../ToolchainGCC.cmake \
  -DCMAKE_EXE_LINKER_FLAGS="-v" \
  -DCMAKE_PREFIX_PATH=/muslsysroot/share/cmake/libddwaf \
  -DLIBDDWAF_SMOKE_LINK_STATIC=ON \
  -DLIBDDWAF_SMOKE_LINK_STATIC_FLAGS="-Wl,--push-state -Wl,-L/muslsysroot/lib -l:libc++.a -l:libc++experimental.a -l:libc++abi.a -l:libunwind.a -Wl,--pop-state" \
  ../../../../../smoketest
make
