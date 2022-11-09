#!/bin/bash
set -eu

export CC=clang
export CXX=clang++

rm -rf build && mkdir build && cd build

cmake -DCMAKE_VERBOSE_MAKEFILE=1 -DCMAKE_BUILD_TYPE=Release ..

make -j $(nproc) fuzzer

cp fuzzing/fuzzer ../fuzzing/
