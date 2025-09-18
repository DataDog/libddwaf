// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <memory>
#include <string_view>

#include "builder/checksum_builder.hpp"
#include "checksum/base.hpp"
#include "checksum/luhn_checksum.hpp"
#include "configuration/common/parser_exception.hpp"

using namespace std::literals;

namespace ddwaf {

std::unique_ptr<base_checksum> checksum_builder::build(std::string_view name)
{
    if (name == "luhn") {
        return std::make_unique<luhn_checksum>();
    }

    // NOLINTNEXTLINE(misc-include-cleaner)
    throw parsing_error(fmt::format("unknown checksum algorithm: '{}'", name));
}

} // namespace ddwaf
