// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "utils.hpp"
#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "checksum/luhn_checksum.hpp"

namespace ddwaf {

bool luhn_checksum::validate(std::string_view str) const noexcept
{
    // Precomputed doubled values
    //   for num from 0 to 9: (2 * num) / 10 + (2 * num) % 10
    static constexpr std::array<uint8_t, 10> lut = {0, 2, 4, 6, 8, 1, 3, 5, 7, 9};

    uint32_t sum = 0;
    bool should_double = false;
    bool digits_seen = false;
    for (std::size_t i = str.size(); i > 0; --i) {
        const auto c = str[i - 1];
        if (!ddwaf::isdigit(c)) {
            continue;
        }

        digits_seen = true;
        const auto d = static_cast<uint32_t>(c - '0');
        sum += should_double ? lut[d] : d;
        should_double = !should_double;
    }

    return digits_seen && (sum % 10U == 0U);
}

} // namespace ddwaf
