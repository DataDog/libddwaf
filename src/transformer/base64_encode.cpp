// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer/base64_encode.hpp"
#include <array>

namespace ddwaf::transformer {

bool base64_encode::transform_impl(cow_string &str)
{
    if (str.length() >= UINT64_MAX / 4 * 3) {
        return false;
    }

    // We need to allocate a buffer to contain the base64 encoded string
    size_t encoded_length = (str.length() + 2) / 3 * 4;
    char *new_string = static_cast<char *>(malloc(encoded_length + 1));

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

    if (read != str.length()) {
        // We want to keep our logic simple so let's copy the bytes left in an appropriately sized
        // buffer
        //  We know that must have either one, or two bytes to process (otherwise the loop above
        //  would have run one more time)
        const std::array<uint8_t, 2> originalBytes{
            str.at(read), read + 1 == str.length() ? 0 : str.at(read + 1)};

        // Compute the codes, only three as the forth is only set by the third, missing input byte
        const std::array<uint8_t, 3> convertedBytes{static_cast<uint8_t>(originalBytes[0] >> 2),
            static_cast<uint8_t>((originalBytes[0] & 0x3) << 4 | (originalBytes[1] >> 4)),
            static_cast<uint8_t>((originalBytes[1] & 0xf) << 2)};

        // The first byte is always set in this branch, so no matter what we must set the first two
        // bytes in the output
        new_string[write++] = b64Encoding[convertedBytes[0]];
        new_string[write++] = b64Encoding[convertedBytes[1]];

        // If we had 2 bytes to encode, we'll encode it
        // Otherwise, we will pad the end
        if (++read != str.length()) {
            new_string[write++] = b64Encoding[convertedBytes[2]];
        } else {
            new_string[write++] = '=';
        }

        new_string[write++] = '=';
    }

    new_string[write] = 0;

    str.replace_buffer(new_string, write);

    return true;
}

} // namespace ddwaf::transformer
