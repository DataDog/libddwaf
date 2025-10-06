// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>
#include <string_view>
#include <utility>

#include "cow_string.hpp"
#include "dynamic_string.hpp"
#include "matcher/hidden_ascii_match.hpp"
#include "transformer/unicode_normalize.hpp"
#include "utf8.hpp"

using namespace ddwaf::utf8;

namespace ddwaf::matcher {

std::pair<bool, dynamic_string> hidden_ascii_match::match_impl(std::string_view pattern)
{
    uint32_t codepoint;
    uint64_t position = 0;

    // Find the first unicode character
    while (position < pattern.length() && static_cast<uint8_t>(pattern[position]) <= 0x7F) {
        ++position;
    }

    bool hidden_ascii_found = false;
    while ((codepoint = fetch_next_codepoint(pattern.data(), position, pattern.length())) !=
           UTF8_EOF) {
        // Ignore invalid glyphs
        if (codepoint >= 0xE0000 && codepoint <= 0xE007F) {
            hidden_ascii_found = true;
            break;
        }
    }

    if (!hidden_ascii_found) {
        return {false, {}};
    }

    cow_string str{pattern};
    // The transformation shouldn't fail
    transformer::unicode_normalize::transform(str);
    return {true, static_cast<dynamic_string>(str)};
}

} // namespace ddwaf::matcher
