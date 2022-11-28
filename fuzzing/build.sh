#!/bin/bash
set -eu

export CC=clang-14
export CXX=clang++-14

rm -rf build && mkdir build && cd build

cmake -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_BUILD_TYPE=Release ..

make -j $(nproc) fuzzer

cp fuzzing/fuzzer ../fuzzing/
