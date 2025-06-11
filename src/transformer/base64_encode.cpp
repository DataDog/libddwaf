// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <limits>

#include "cow_string.hpp"
#include "memory_resource.hpp" // IWYU pragma: keep
#include "transformer/base64_encode.hpp"

namespace ddwaf::transformer {

bool base64_encode::transform_impl(cow_string &str)
{
    if (str.length() >= std::numeric_limits<std::size_t>::max() / 4 * 3) {
        return false;
    }

    // We need to allocate a buffer to contain the base64 encoded string
    const size_t encoded_length = (str.length() + 2) / 3 * 4;

    // NOLINTNEXTLINE(misc-include-cleaner)
    auto *alloc = std::pmr::get_default_resource();
    auto *new_string = static_cast<char *>(alloc->allocate(encoded_length, alignof(char)));

    // We don't have a good way to make this test fail in the CI, thus crapping on the coverage
    if (new_string == nullptr) {
        return false;
    }

    static constexpr std::array<char, 66> b64Encoding{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I',
        'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a',
        'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
        't', 'u', 'v', 'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+',
        '-'};

    uint64_t read = 0;
    uint64_t write = 0;

    for (; read + 2 < str.length(); read += 3) {
        const std::array<uint8_t, 4> quartet{str.at<uint8_t>(read) >> 2,
            (str.at<uint8_t>(read) & 0x3) << 4 | (str.at<uint8_t>(read + 1) >> 4),
            (str.at<uint8_t>(read + 1) & 0xf) << 2 | str.at<uint8_t>(read + 2) >> 6,
            str.at<uint8_t>(read + 2) & 0x3f};

        new_string[write++] = b64Encoding[quartet[0]];
        new_string[write++] = b64Encoding[quartet[1]];
        new_string[write++] = b64Encoding[quartet[2]];
        new_string[write++] = b64Encoding[quartet[3]];
    }

    if (read < str.length()) {
        //  We know that must have either one, or two bytes to process
        //  (otherwise the loop above would have run one more time)
        const uint8_t first_byte = str.at<uint8_t>(read) >> 2;
        uint8_t second_byte = (str.at<uint8_t>(read) & 0x3) << 4;

        new_string[write++] = b64Encoding[first_byte];

        if (read + 1 >= str.length()) {

            new_string[write++] = b64Encoding[second_byte];
            // Pad the end
            new_string[write++] = '=';
        } else {
            // Compute the codes, only three as the forth is only set by the third,
            // missing input byte
            second_byte |= (str.at<uint8_t>(read + 1) >> 4);
            const uint8_t third_byte = (str.at<uint8_t>(read + 1) & 0xf) << 2;

            new_string[write++] = b64Encoding[second_byte];
            // If we had 2 bytes to encode, we'll encode it
            new_string[write++] = b64Encoding[third_byte];
        }

        new_string[write++] = '=';
    }

    // NOLINTNEXTLINE(readability-suspicious-call-argument)
    str.replace_buffer(new_string, write, encoded_length);

    return true;
}

} // namespace ddwaf::transformer
