// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "../common/afl_wrapper.hpp"
#include "../common/utils.hpp"
#include "processor/fingerprint.hpp"
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
    random_buffer buffer{data, size};

    ddwaf_object tmp;

    // Create cookies object
    ddwaf_object cookies;
    ddwaf_object_map(&cookies);
    auto cookies_size = buffer.get<uint8_t>();
    for (uint8_t i = 0; i < cookies_size; ++i) {
        auto key = buffer.get<std::string_view>();
        auto value = buffer.get<std::string_view>();

        ddwaf_object_map_addl(&cookies, key.data(), key.size(),
            ddwaf_object_stringl(&tmp, value.data(), value.size()));
    }

    // Create session fingerprint processor
    session_fingerprint gen{"id", {}, {}, false, true};

    // Execute processor
    processor_cache cache;
    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{{}, {}, false, &cookies}},
        {{{}, {}, false, buffer.get<std::string_view>()}},
        {{{}, {}, false, buffer.get<std::string_view>()}}, cache, deadline);

    // Clean up
    ddwaf_object_free(&cookies);
    ddwaf_object_free(&output);

    return 0;
}

// Create AFL++ main function with initialization
AFL_FUZZ_TARGET_WITH_INIT("session_fingerprint_fuzz", LLVMFuzzerTestOneInput, LLVMFuzzerInitialize)