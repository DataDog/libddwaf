#!/bin/bash
set -eu

cd fuzzer/global

llvm-profdata-17 merge -sparse *.profraw -o default.profdata
llvm-cov-17 show global_fuzzer -instr-profile=default.profdata -ignore-filename-regex="(vendor|fuzzer|third_party)" -format=html > coverage.html
llvm-cov-17 report -instr-profile default.profdata global_fuzzer -ignore-filename-regex="(vendor|fuzzer|third_party)" -show-region-summary=false

if [ ! -z ${1:-} ]; then 
    THRESHOLD=$1
    TOTAL=$(llvm-cov-17 report -instr-profile default.profdata global_fuzzer -ignore-filename-regex="(vendor|fuzzer|third_party)" -show-region-summary=false | grep TOTAL)
    ARRAY=($TOTAL)
    COVERAGE=$(echo ${ARRAY[3]} | sed -e "s/\.[[:digit:]]*%//g")

    if (( $COVERAGE < $THRESHOLD )); then
        echo "Sorry, the fuzzer found no bug, but the coverage is below $THRESHOLD%. Can't call it a success." 1>&2
        exit 1
    fi
fi
