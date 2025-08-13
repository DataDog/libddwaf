// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "../common/afl_wrapper.hpp"
#include "../common/utils.hpp"
#include "sha256.hpp"
#include <cstdint>

using namespace ddwaf_afl;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Create SHA256 hasher
    ddwaf::sha256_hash hasher;

    // Process the input data
    auto input_view = bytes_to_string_view(data, size);
    hasher << input_view;

    // Get the digest
    auto result = hasher.digest();

    // Prevent compiler optimization
    prevent_optimization(result);

    return 0;
}

// Create AFL++ main function
AFL_FUZZ_TARGET("sha256_fuzz", LLVMFuzzerTestOneInput)