// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "../common/afl_wrapper.hpp"
#include "../common/utils.hpp"
#include "processor/jwt_decode.hpp"
#include <cstdint>

using namespace ddwaf;
using namespace ddwaf_afl;
using namespace std::literals;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    // Set up memory resource
    ddwaf::memory::set_local_memory_resource(std::pmr::new_delete_resource());
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    // Create ddwaf objects
    ddwaf_object tmp;
    ddwaf_object headers;
    ddwaf_object_map(&headers);

    // Add authorization header with fuzzer input
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_stringl(&tmp, reinterpret_cast<const char *>(data), size));

    // Create JWT decode processor
    jwt_decode gen{"id", {}, {}, false, true};

    // Execute processor
    processor_cache cache;
    ddwaf::timer deadline{2s};
    static const std::vector<std::string> key_path{"authorization"};
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);

    // Clean up
    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);

    return 0;
}

// Create AFL++ main function with initialization
AFL_FUZZ_TARGET_WITH_INIT("jwt_decode_fuzz", LLVMFuzzerTestOneInput, LLVMFuzzerInitialize)