#!/bin/bash

# Script to run AFL++ fuzzers for a few seconds each and generate coverage report
# Usage: ./run_all_fuzzers.sh [fuzzer_name]
#   - No argument or "all": Run all fuzzers
#   - fuzzer_name: Run specific fuzzer

set -e

PROJECT_ROOT="/workspace"
FUZZER_BUILD_DIR="$PROJECT_ROOT/fuzzer/build"
OUTPUT_DIR="$PROJECT_ROOT/o"
FUZZER_TIMEOUT=10s

# Check if we're in the container environment
if [[ ! -f "/opt/build.sh" ]]; then
    echo "Warning: This script is designed to run in the fuzz container."
    echo "Consider running: docker run --rm -v \$(pwd):/workspace fuzzer-image ./fuzzer/run_all_fuzzers.sh [fuzzer_name]"
fi

cd "$PROJECT_ROOT"

# Create output directories
mkdir -p "$OUTPUT_DIR"

# Define all fuzzers based on the available binaries
# TODO: automatically detect all fuzzers in the build directory
ALL_FUZZERS=(
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

# Parse command line arguments
TARGET_FUZZER="$1"

# Determine which fuzzers to run
if [[ -z "$TARGET_FUZZER" || "$TARGET_FUZZER" == "all" ]]; then
    FUZZERS=("${ALL_FUZZERS[@]}")
    echo "=== Running ALL AFL++ fuzzers for a few seconds each ==="
    echo "Found ${#FUZZERS[@]} fuzzers to run"
else
    # Check if the specified fuzzer exists in the list
    if [[ " ${ALL_FUZZERS[*]} " =~ " $TARGET_FUZZER " ]]; then
        FUZZERS=("$TARGET_FUZZER")
        echo "=== Running $TARGET_FUZZER fuzzer ==="
    else
        echo "❌ Error: Fuzzer '$TARGET_FUZZER' not found."
        echo "Available fuzzers:"
        printf "  - %s\n" "${ALL_FUZZERS[@]}"
        exit 1
    fi
fi

echo ""

# Function to run a single fuzzer and generate its coverage
run_fuzzer() {
    local fuzzer_name="$1"
    local binary="$FUZZER_BUILD_DIR/${fuzzer_name}_fuzz"
    local corpus_dir="$PROJECT_ROOT/fuzzer/$fuzzer_name/corpus"
    local output_dir="$OUTPUT_DIR/$fuzzer_name"
    local coverage_dir="$OUTPUT_DIR/$fuzzer_name"
    
    if [[ ! -f "$binary" ]]; then
        echo "❌ Binary not found: $binary"
        return 1
    fi
    
    if [[ ! -d "$corpus_dir" ]]; then
        echo "❌ Corpus directory not found: $corpus_dir"
        return 1
    fi
    
    echo "🚀 Running $fuzzer_name fuzzer..."
    echo "   Binary: $binary"
    echo "   Corpus: $corpus_dir"
    echo "   Output: $output_dir"
    echo "   Coverage: $coverage_dir"
    
    # Clean up previous output for this fuzzer
    rm -rf "$output_dir"
    rm -rf "$coverage_dir"
    mkdir -p "$output_dir"
    mkdir -p "$coverage_dir"
    
    # Set AFL environment variables
    export AFL_SKIP_CPUFREQ=1
    export AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1
    export AFL_FAST_CAL=1
    
    # Run AFL++ with timeout
    timeout $FUZZER_TIMEOUT afl-fuzz -i "$corpus_dir" -o "$output_dir" -D "$binary" || {
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            echo "✅ $fuzzer_name completed (60s timeout reached)"
        else
            echo "⚠️  $fuzzer_name exited with code $exit_code"
        fi
    }
    
    # Generate individual coverage report for this fuzzer
    echo "📊 Generating coverage for $fuzzer_name..."
    echo "   Coverage output: $coverage_dir"
    
    # Run afl-cov-fast for this specific fuzzer
    /opt/afl-cov-fast/afl-cov-fast.py \
        -m llvm \
        --code-dir "$PROJECT_ROOT" \
        --afl-fuzzing-dir "$output_dir" \
        --coverage-cmd "$binary" \
        --binary-path "$binary" \
        -j$(nproc) || {
        echo "⚠️  Coverage generation failed for $fuzzer_name"
    }
    
    echo "✅ $fuzzer_name fuzzing and coverage complete"
    echo ""
}

# Run all fuzzers sequentially
for fuzzer in "${FUZZERS[@]}"; do
    run_fuzzer "$fuzzer"
done

echo "=== All fuzzers completed ==="
echo ""
echo "=== Individual Coverage Reports Generated ==="
echo "📊 Coverage reports available for each fuzzer:"
echo ""

# Display coverage report locations for each fuzzer
for fuzzer in "${FUZZERS[@]}"; do
    index_file="$OUTPUT_DIR/$fuzzer/cov/web/index.html"
    if [[ -f "$index_file" ]]; then
        echo "✅ $fuzzer: $index_file"
    else
        echo "❌ $fuzzer: Coverage report not found"
    fi
done

echo ""
echo ""

# find all fuzzers that have any amount of crashing files created
for fuzzer in "${FUZZERS[@]}"; do
    if [[ -d "$OUTPUT_DIR/$fuzzer/default/crashes" ]] && [[ -n "$(ls -A "$OUTPUT_DIR/$fuzzer/default/crashes" 2>/dev/null)" ]]; then
        crash_count=$(ls -1 "$OUTPUT_DIR/$fuzzer/default/crashes" 2>/dev/null | wc -l)
        echo "❌ Crash found for $fuzzer: $crash_count files in $OUTPUT_DIR/$fuzzer/default/crashes"
    fi
done