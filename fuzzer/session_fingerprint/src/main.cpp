// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>

#include "common.hpp"
#include "memory_resource.hpp"
#include <processor/fingerprint.hpp>

using namespace ddwaf;
using namespace std::literals;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    random_buffer buffer{bytes, size};

    auto cookies = owned_object::make_map(0, ddwaf::memory::get_default_resource());
    auto cookies_size = buffer.get<uint8_t>();
    for (uint8_t i = 0; i < cookies_size; ++i) {
        auto key = buffer.get<std::string_view>();
        auto value = buffer.get<std::string_view>();

        cookies.emplace(key, value);
    }

    session_fingerprint gen{"id", {}, {}, false, true};

    processor_cache cache;
    ddwaf::timer deadline{2s};

    auto output = gen.eval_impl({{.address = {}, .key_path = {}, .value = cookies}},
        {{.address = {}, .key_path = {}, .value = buffer.get<std::string_view>()}},
        {{.address = {}, .key_path = {}, .value = buffer.get<std::string_view>()}}, cache,
        ddwaf::memory::get_default_resource(), deadline);

    return 0;
}
