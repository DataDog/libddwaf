#!/bin/bash
set -eu

cd fuzzer/global

rm -f fuzz-*.log
rm -f sample_dict.txt sample_rules.yml
rm -f default.profdata default.profraw coverage.html
rm -rf global_fuzzer.dSYM
rm -rf global_fuzzer
