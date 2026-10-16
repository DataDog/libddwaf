// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "cow_string.hpp"
#include "transformer/byte_scan.hpp"
#include "transformer/unicode_normalize.hpp"
#include "utf8.hpp"

using namespace ddwaf::utf8;

namespace ddwaf::transformer {

namespace {

struct is_non_ascii {
    template <typename T> static auto match(T c)
    { return byte_scan::in_range(c, static_cast<char>(0x80), static_cast<char>(0xFF)); }
};

} // namespace

bool unicode_normalize::needs_transform(std::string_view str)
{
    uint32_t codepoint;
    uint64_t position = 0;
    while (true) {
        // ASCII characters are single-byte code points which never need
        // normalization, so the next code point to check starts at the next
        // non-ASCII byte
        position = byte_scan::find_first<is_non_ascii>(str.data(), str.length(), position);
        codepoint = fetch_next_codepoint(str.data(), position, str.length());
        if (codepoint == UTF8_EOF) {
            break;
        }

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
