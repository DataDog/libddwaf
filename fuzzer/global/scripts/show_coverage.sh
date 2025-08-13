#!/bin/bash
set -eu

FUZZ_PATH=/workspace/fuzzer/build/global_fuzz
AFL_OUTPUT_DIR=/workspace/o
PROFDATA_PATH=/workspace/o/cov/lcov/default.profdata

# https://github.com/airbus-seclab/afl-cov-fast
/opt/afl-cov-fast/afl-cov-fast.py -c . -m llvm -e $FUZZ_PATH -b $FUZZ_PATH -d $AFL_OUTPUT_DIR -j $(nproc) -O

# llvm-profdata-19 merge -sparse *.profraw -o default.profdata
llvm-cov-19 report -instr-profile=$PROFDATA_PATH $FUZZ_PATH -ignore-filename-regex="(vendor|fuzzer|third_party)" -show-region-summary=false

echo "--------------------------------"
echo "You can open o/cov/web/index.html in your browser to see the coverage report in a human friendly way"
echo "--------------------------------"

if [ ! -z ${1:-} ]; then 
    THRESHOLD=$1
    TOTAL=$(llvm-cov-19 report -instr-profile=$PROFDATA_PATH $FUZZ_PATH -ignore-filename-regex="(vendor|fuzzer|third_party)" -show-region-summary=false | grep TOTAL)
    ARRAY=($TOTAL)
    COVERAGE=$(echo ${ARRAY[3]} | sed -e "s/\.[[:digit:]]*%//g")

    if (( $COVERAGE < $THRESHOLD )); then
        echo "Sorry, the fuzzer found no bug, but the coverage is below $THRESHOLD%. Can't call it a success." 1>&2
        exit 1
    fi
fi
