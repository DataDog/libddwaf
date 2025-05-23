// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>

#include "common.hpp"
#include <processor/fingerprint.hpp>

using namespace ddwaf;
using namespace std::literals;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    static std::array<std::string_view, 8> headers{"x-forwarded-for", "x-real-ip", "x-client-ip",
        "forwarded-for", "x-cluster-client-ip", "fastly-client-ip", "cf-connecting-ip",
        "cf-connecting-ipv6"};

    random_buffer buffer{bytes, size};

    ddwaf_object tmp;

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

    http_network_fingerprint gen{"id", {}, {}, false, true};

    processor_cache cache;
    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl(
        {.address = {}, .key_path = {}, .ephemeral = false, .value = &header}, cache, deadline);

    ddwaf_object_free(&header);

    return 0;
}
