#!/bin/bash
set -eu

cp build/fuzzing/fuzzer fuzzing/fuzzer
python3 fuzzing/scripts/build_corpus.py

cd fuzzing

export ASAN_OPTIONS=detect_leaks=1

rm -f fuzz-*.log

echo "Run fuzzer for ${1:-30} seconds"
./fuzzer -timeout=0.1 -report_slow_units=0.01 -max_total_time=${1:-30} -max_len=1000 -rss_limit_mb=4096 -use_value_profile=1 -dict=sample_dict.txt -artifact_prefix=results/ -jobs=4 -workers=4 -reload=0 corpus
# ./fuzzer -timeout=0.1 -report_slow_units=0.01 -max_total_time=${1:-30} -max_len=1000 -rss_limit_mb=4096 -use_value_profile=1 -dict=sample_dict.txt -artifact_prefix=results/ -reload=0 corpus