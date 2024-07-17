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
    random_buffer buffer{bytes, size};

    ddwaf_object tmp;

    ddwaf_object header;
    ddwaf_object_map(&header);
    auto header_size = buffer.get<uint8_t>();
    for (uint8_t i = 0; i < header_size; ++i) {
        auto key = buffer.get<std::string_view>();
        auto value = buffer.get<std::string_view>();

        ddwaf_object_map_addl(&header, key.data(), key.size(),
            ddwaf_object_stringl(&tmp, value.data(), value.size()));
    }

    http_network_fingerprint gen{"id", {}, {}, false, true};

    ddwaf::timer deadline{2s};
    auto [output, attr] = gen.eval_impl({{}, {}, false, &header}, deadline);

    ddwaf_object_free(&header);
    ddwaf_object_free(&output);

    return 0;
}
