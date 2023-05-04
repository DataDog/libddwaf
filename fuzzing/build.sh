#!/bin/bash
set -eu

export CC=clang-15
export CXX=clang++-15

rm -rf build && mkdir build && cd build

cmake -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_BUILD_TYPE=RelWithDebInfo ..

make -j $(nproc) fuzzer

cp fuzzing/fuzzer ../fuzzing/
