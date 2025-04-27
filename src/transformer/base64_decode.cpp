// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "transformer/base64_decode.hpp"
#include "transformer/common/cow_string.hpp"
#include "utils.hpp"

namespace ddwaf::transformer {

namespace {

bool decode_common(cow_string &str, const std::array<char, 256> &b64Reverse)
{
    /*
     * We ignore the invalid characters in this loop as `needs_transform` will
     * prevent decoding invalid sequences
     */
    size_t read = 0;
    size_t write = 0;
    while (read < str.length()) {
        // Read the next 4 b64 bytes
        std::array<char, 4> quartet{0, 0, 0, 0};
        size_t pos = 0;

        for (; pos < 4 && read < str.length(); ++read) {
            // If a valid base64url character
            auto idx = str.at<uint8_t>(read);
            auto c = b64Reverse[idx];
            if ((c & 0x40) == 0) {
                quartet[pos++] = c;
            }
        }

        // Coalesce 4x 6 bits into 3x 8 bits
        auto value = quartet[0] << 18 | quartet[1] << 12 | quartet[2] << 6 | quartet[3];

        // Convert to bytes
        std::array<char, 3> bytes{static_cast<char>(value >> 16),
            static_cast<char>((value >> 8) & 0xff), static_cast<char>(value & 0xff)};

        // Simple write
        if (pos == 4) {
            str[write++] = bytes[0];
            str[write++] = bytes[1];
            str[write++] = bytes[2];
        } else if (pos != 0) {
            // This is the final write, we shouldn't write every byte
            // We match CRS behavior of partially decoding a character
            //
            // If pos == 1, we have 6 bits of content, 1 char to write
            // If pos == 2, we have 12 bits of content, 2 char to write
            // If pos == 3, we have 18 bits of content, 3 char to write
            str[write++] = bytes[0];

            // At least 12 bits of content, only write if either this of the next byte isn't empty
            if (pos > 1 && ((bytes[1] != 0) || (bytes[2] != 0))) {
                str[write++] = bytes[1];
            }

            // At least 18 bits of content and non-null
            if (pos > 2 && bytes[2] != 0) {
                str[write++] = bytes[2];
            }
        }
    }

    str.truncate(write);

    return true;
}

} // namespace

bool base64_decode::needs_transform(std::string_view str)
{
    // All characters must be valid
    for (size_t pos = 0; pos < str.length(); ++pos) {
        if (!ddwaf::isalnum(str[pos]) && str[pos] != '+' && str[pos] != '/') {
            // If it's not a valid base64, it must be the trailing =
            if (str[pos] == '=') {
                size_t equals = 0;
                while (pos + equals < str.length() && str[pos + equals] == '=') { equals += 1; }

                // The = must go to the end, and there musn't be too many
                const size_t padding = 4 - (pos % 4);
                if (pos + equals == str.length() && equals <= 3 && equals <= padding) {
                    continue;
                }
            }

            // Anything wrong -> nope
            return false;
        }
    }

    return true;
}

bool base64_decode::transform_impl(cow_string &str)
{
    static constexpr std::array<char, 256> b64Reverse{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, -1, -1, -1, 64, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33,
        34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

    return decode_common(str, b64Reverse);
}

bool base64url_decode::needs_transform(std::string_view str)
{
    // All characters must be valid
    for (size_t pos = 0; pos < str.length(); ++pos) {
        if (!ddwaf::isalnum(str[pos]) && str[pos] != '-' && str[pos] != '_') {
            // If it's not a valid base64, it must be the trailing =
            if (str[pos] == '=') {
                size_t equals = 0;
                while (pos + equals < str.length() && str[pos + equals] == '=') { equals += 1; }

                // The = must go to the end, and there musn't be too many
                const size_t padding = 4 - (pos % 4);
                if (pos + equals == str.length() && equals <= 3 && equals <= padding) {
                    continue;
                }
            }

            // Anything wrong -> nope
            return false;
        }
    }
    return true;
}

bool base64url_decode::transform_impl(cow_string &str)
{
    static constexpr std::array<char, 256> b64Reverse{-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, 52, 53, 54, 55, 56, 57, 58, 59, 60,
        61, -1, -1, -1, 64, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1, -1, 26, 27, 28, 29, 30, 31, 32, 33,
        34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, 63,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1};

    return decode_common(str, b64Reverse);
}

} // namespace ddwaf::transformer
