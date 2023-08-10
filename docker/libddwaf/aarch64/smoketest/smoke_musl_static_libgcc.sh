#!/bin/bash -e

set -x
mkdir -p musl_static_libgcc
cd musl_static_libgcc
cmake -DCMAKE_C_COMPILER=/muslsysroot/bin/musl-gcc \
  -DCMAKE_SYSROOT=/muslsysroot \
  -DCMAKE_EXE_LINKER_FLAGS="-v" \
  -DCMAKE_PREFIX_PATH=/muslsysroot/share/cmake/libddwaf \
  -DLINK_DDWAF_STATIC=ON \
  -DLIBDDWAF_SMOKETEST_SYSROOT=/muslsysroot/lib \
  ../../../../../smoketest/
make
