// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "../common/afl_wrapper.hpp"
#include "../common/utils.hpp"
#include "tokenizer/shell.hpp"
#include <cstdint>

using namespace ddwaf_afl;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Convert input to string_view for tokenization
    auto query = bytes_to_string_view(data, size);

    // Create tokenizer and tokenize the input
    ddwaf::shell_tokenizer tokenizer(query);
    auto tokens = tokenizer.tokenize();

    // Prevent compiler optimization
    prevent_optimization(tokens);

    return 0;
}

// Create AFL++ main function
AFL_FUZZ_TARGET("shell_tokenizer_fuzz", LLVMFuzzerTestOneInput)