#!/bin/bash
set -eu

cp build/fuzzer/global_fuzzer fuzzer/global/global_fuzzer
python3 fuzzer/global/scripts/build_corpus.py

cd fuzzer/global

export ASAN_OPTIONS="detect_leaks=0,use_stacks=0,verbosity=1,leak_check_at_exit=1"

rm -f fuzz-*.log

echo "Run global fuzzer for ${1:-60} seconds"
./global_fuzzer -timeout=0.1 -report_slow_units=0.01 -max_total_time=${1:-60} -max_len=1000 -rss_limit_mb=4096 -use_value_profile=1 -dict=sample_dict.txt -artifact_prefix=results/ -jobs=4 -workers=4 -reload=0 corpus
