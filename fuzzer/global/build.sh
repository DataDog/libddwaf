#!/bin/bash
set -eu

export CC=clang-17
export CXX=clang++-17

rm -rf build && mkdir build && cd build

cmake -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_BUILD_TYPE=RelWithDebInfo ..

make -j $(nproc) global_fuzzer

cp fuzzer/global_fuzzer ../fuzzer/global/
