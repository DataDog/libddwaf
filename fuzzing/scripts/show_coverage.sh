#!/bin/bash
set -eu

cd fuzzing

llvm-profdata-10 merge -sparse *.profraw -o default.profdata
llvm-cov-10 show fuzzer -instr-profile=default.profdata -ignore-filename-regex="(fuzzing|third_party)" -format=html > coverage.html
llvm-cov-10 report -instr-profile default.profdata fuzzer -ignore-filename-regex="(fuzzing|third_party)"
