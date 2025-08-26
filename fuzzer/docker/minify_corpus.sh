#!/bin/bash

# Script to minify the corpus for all fuzzers

PROJECT_ROOT="/workspace"
FUZZER_BUILD_DIR="$PROJECT_ROOT/fuzzer/build"
AFL_FUZZ_DIR="$PROJECT_ROOT/o"

# Check if we're in the container environment
if [[ ! -f "/opt/build.sh" ]]; then
    echo "Warning: This script is designed to run in the fuzz container."
    echo "Consider running: docker run --rm -v \$(pwd):/workspace fuzzer-image ./fuzzer/docker/minify_corpus.sh"
fi

cd "$PROJECT_ROOT"

# Define all fuzzers based on the available binaries
# TODO: automatically detect all fuzzers in the build directory
FUZZERS=(
    "cmdi_detector"
    "e2e"
    "http_endpoint_fingerprint"
    "http_header_fingerprint"
    "http_network_fingerprint"
    "jwt_decode"
    "lfi_detector"
    "session_fingerprint"
    "sha256"
    "shell_tokenizer"
    "shi_detector_array"
    "shi_detector_string"
    "sql_tokenizer"
    "sqli_detector"
    "ssrf_detector"
    "uri_parse"
    "global"
)


for fuzzer in "${FUZZERS[@]}"; do
    echo "Starting minification for $fuzzer..."
    echo "deleting previous minified corpus..."
    rm -rf corpus_minified_$fuzzer
    # We move all the new things in the queue
    echo "Moving new things in the queue to the native corpus..."
    cp -f $AFL_FUZZ_DIR/$fuzzer/default/queue/* $PROJECT_ROOT/fuzzer/$fuzzer/corpus/

    echo "Minifying corpus..."
    afl-cmin -T $(nproc) -i $PROJECT_ROOT/fuzzer/$fuzzer/corpus -o corpus_minified_$fuzzer $FUZZER_BUILD_DIR/${fuzzer}_fuzz
    
    echo "Cleaning up old corpus and previous minified corpus..."
    rm -rf $PROJECT_ROOT/fuzzer/$fuzzer/corpus/*
    mkdir -p $PROJECT_ROOT/fuzzer/$fuzzer/corpus/
    mv corpus_minified_$fuzzer/* $PROJECT_ROOT/fuzzer/$fuzzer/corpus/
    rm -rf corpus_minified_$fuzzer
    echo "Done"
done