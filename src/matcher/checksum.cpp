// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "matcher/checksum.hpp"
#include "utils.hpp"
#include <cstddef>
#include <stdexcept>
#include <string_view>

namespace ddwaf {

namespace {

bool luhn_checksum(std::string_view str)
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

} // namespace

checksum_algorithm checksum_algorithm_from_string(std::string_view str)
{
    if (str == "luhn") {
        return checksum_algorithm::luhn;
    }

    if (str == "none") {
        return checksum_algorithm::none;
    }

    throw std::invalid_argument("unknown check digit algorithm");
}

bool checksum_eval(checksum_algorithm algo, std::string_view str)
{
    switch (algo) {
    case checksum_algorithm::luhn:
        return luhn_checksum(str);
    case checksum_algorithm::none:
        return true;
    default:
        break;
    }
    return false;
}

} // namespace ddwaf
