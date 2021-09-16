#!/bin/bash
set -eu

cd fuzzing

rm -rf corpus/
rm -f fuzz-*.log
rm -f sample_dict.txt sample_rules.yml
rm -f default.profdata default.profraw coverage.html
rm -rf fuzzer.dSYM
rm -rf fuzzer
