#!/bin/bash -e

set -x
mkdir -p gnu_shared
cd gnu_shared
cmake -DCMAKE_TOOLCHAIN_FILE=../../ToolchainGCC.cmake \
  -DCMAKE_PREFIX_PATH=/muslsysroot/share/cmake/libddwaf \
  -DCMAKE_EXE_LINKER_FLAGS="-v -Wl,-rpath=/muslsysroot/lib" \
  -DLINK_DDWAF_STATIC=OFF \
  ../../../../../smoketest
make
