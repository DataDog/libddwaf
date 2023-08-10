#!/bin/bash -e

set -x
mkdir -p gnu_static
cd gnu_static
cmake -DCMAKE_TOOLCHAIN_FILE=../../ToolchainGCC.cmake \
  -DCMAKE_EXE_LINKER_FLAGS="-v" \
  -DCMAKE_PREFIX_PATH=/muslsysroot/share/cmake/libddwaf \
  -DLINK_DDWAF_STATIC=ON \
  -DLIBDDWAF_SMOKETEST_SYSROOT=/muslsysroot/lib \
  ../../../../../smoketest
make
