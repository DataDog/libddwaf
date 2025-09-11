// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "utils.hpp"
#include <cstddef>
#include <string_view>

#include "checksum/luhn_checksum.hpp"

namespace ddwaf {

bool luhn_checksum::validate_impl(std::string_view str) noexcept
{
    unsigned check_digit = 0;
    std::size_t i = str.size();
    for (; i > 0; --i) {
        auto c = str[i - 1];
        if (!ddwaf::isdigit(c)) {
            continue;
        }

        check_digit = (c - '0');
        break;
    }

    if (i == 0) {
        return false;
    }

    unsigned total = 0;
    unsigned count = 0;
    for (i -= 1; i > 0; --i) {
        auto c = str[i - 1];
        if (!ddwaf::isdigit(c)) {
            continue;
        }

        unsigned num = c - '0';
        if ((count++ & 0x01) == 0) {
            num = (2 * num) / 10 + (2 * num) % 10;
        }
        total += num;
    }

    auto computed_digit = ((10 - (total % 10)) % 10);

    return computed_digit == check_digit;
}

} // namespace ddwaf
