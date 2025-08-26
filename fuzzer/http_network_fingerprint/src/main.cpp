// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "../common/afl_wrapper.hpp"
#include "../common/utils.hpp"
#include "processor/fingerprint.hpp"
#include <array>
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
    static std::array<std::string_view, 8> headers{"x-forwarded-for", "x-real-ip", "x-client-ip",
        "forwarded-for", "x-cluster-client-ip", "fastly-client-ip", "cf-connecting-ip",
        "cf-connecting-ipv6"};

    random_buffer buffer{data, size};

    ddwaf_object tmp;

    // Create header object
    ddwaf_object header;
    ddwaf_object_map(&header);
    auto header_size = buffer.get<uint8_t>();
    for (uint8_t i = 0; i < header_size; ++i) {
        auto value = buffer.get<std::string_view>();

        std::string_view key;
        if (buffer.get<bool>()) { // Known header
            key = headers[buffer.get<uint8_t>() % headers.size()];
        } else {
            key = buffer.get<std::string_view>();
        }
        ddwaf_object_map_addl(&header, key.data(), key.size(),
            ddwaf_object_stringl(&tmp, value.data(), value.size()));
    }

    // Create HTTP network fingerprint processor
    http_network_fingerprint gen{"id", {}, {}, false, true};

    // Execute processor
    processor_cache cache;
    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &header}, cache, deadline);

    // Clean up
    ddwaf_object_free(&header);
    ddwaf_object_free(&output);

    return 0;
}

// Create AFL++ main function with initialization
AFL_FUZZ_TARGET_WITH_INIT(
    "http_network_fingerprint_fuzz", LLVMFuzzerTestOneInput, LLVMFuzzerInitialize)