// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/unicode_normalize.hpp"
#include "transformer/common/cow_string.hpp"
#include "transformer/common/utf8.hpp"
#include <cstddef>
#include <cstdint>
#include <string_view>

using namespace ddwaf::utf8;

namespace ddwaf::transformer {
bool unicode_normalize::needs_transform(std::string_view str)
{
    uint32_t codepoint;
    uint64_t position = 0;
    while ((codepoint = fetch_next_codepoint(str.data(), position, str.length())) != UTF8_EOF) {
        // Ignore invalid glyphs or Zero-Width joiners (which we allow for emojis)
        if (codepoint == UTF8_INVALID || codepoint < 0x80) {
            continue;
        }

        int32_t decomposed_codepoint = 0;
        const size_t decomposed_length =
            ddwaf::utf8::normalize_codepoint(codepoint, &decomposed_codepoint, 1);

        // If the glyph needed decomposition, we flag the string
        if (decomposed_length != 1 || codepoint != static_cast<uint32_t>(decomposed_codepoint)) {
            return true;
        }
    }
    return false;
}

bool unicode_normalize::transform_impl(cow_string &str) { return utf8::normalize_string(str); }

} // namespace ddwaf::transformer
