// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "../common/afl_wrapper.hpp"
#include "../common/utils.hpp"
#include "tokenizer/generic_sql.hpp"
#include "tokenizer/mysql.hpp"
#include "tokenizer/pgsql.hpp"
#include "tokenizer/sqlite.hpp"
#include <cstdint>

using namespace ddwaf_afl;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Need at least one byte to determine tokenizer type
    if (size == 0) {
        return 0;
    }

    // Use first byte to select tokenizer type (modulo 4 for 4 tokenizers)
    uint8_t tokenizer_type = data[0] % 4;

    // Convert remaining input to string_view for tokenization
    auto query = bytes_to_string_view(data + 1, size - 1);

    std::vector<ddwaf::sql_token> tokens;

    // Create appropriate SQL tokenizer based on the first byte
    switch (tokenizer_type) {
    case 0: {
        ddwaf::generic_sql_tokenizer tokenizer(query);
        tokens = tokenizer.tokenize();
        break;
    }
    case 1: {
        ddwaf::mysql_tokenizer tokenizer(query);
        tokens = tokenizer.tokenize();
        break;
    }
    case 2: {
        ddwaf::pgsql_tokenizer tokenizer(query);
        tokens = tokenizer.tokenize();
        break;
    }
    case 3: {
        ddwaf::sqlite_tokenizer tokenizer(query);
        tokens = tokenizer.tokenize();
        break;
    }
    default:
        // This should never happen due to modulo 4, but just in case we crash.
        // TODO: find a way to avoid the fuzzer to silently never cover a new tokenizer if one is
        // added.
        __builtin_trap();
    }

    // Prevent compiler optimization
    prevent_optimization(tokens);

    return 0;
}

// Create AFL++ main function
AFL_FUZZ_TARGET("sql_tokenizer_fuzz", LLVMFuzzerTestOneInput)