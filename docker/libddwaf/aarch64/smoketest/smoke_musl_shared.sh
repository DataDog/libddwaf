#!/bin/bash -e

set -x
mkdir -p musl_shared
cd musl_shared
cmake -DCMAKE_C_COMPILER=/muslsysroot/bin/musl-gcc \
  -DCMAKE_SYSROOT=/muslsysroot \
  -DCMAKE_EXE_LINKER_FLAGS="-v -Wl,-rpath=/muslsysroot/lib" \
  -DCMAKE_PREFIX_PATH=/muslsysroot/share/cmake/libddwaf \
  -DLIBDDWAF_SMOKE_LINK_STATIC=OFF \
  ../../../../../smoketest
make
