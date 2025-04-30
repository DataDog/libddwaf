// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>

#include "common.hpp"
#include <processor/jwt_decode.hpp>

using namespace ddwaf;
using namespace std::literals;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *bytes, size_t size)
{
    ddwaf_object tmp;

    ddwaf_object headers;
    ddwaf_object_map(&headers);
    ddwaf_object_map_add(&headers, "authorization",
        ddwaf_object_stringl(&tmp, reinterpret_cast<const char *>(bytes), size));

    jwt_decode gen{"id", {}, {}, false, true};

    processor_cache cache;
    ddwaf::timer deadline{2s};
    static const std::vector<std::string> key_path{"authorization"};
    auto [output, attr] =
        gen.eval_impl({.address = {}, .key_path = key_path, .ephemeral = false, .value = &headers},
            cache, deadline);

    ddwaf_object_free(&headers);
    ddwaf_object_free(&output);

    return 0;
}
