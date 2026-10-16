// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <string_view>

#include "cow_string.hpp"
#include "transformer/byte_scan.hpp"
#include "transformer/lowercase.hpp"
#include "utils.hpp"

namespace ddwaf::transformer {

namespace {

struct is_upper {
    template <typename T> static auto match(T c) { return byte_scan::in_range(c, 'A', 'Z'); }
};

} // namespace

bool lowercase::needs_transform(std::string_view str)
{ return byte_scan::find_first<is_upper>(str.data(), str.size()) < str.size(); }

bool lowercase::transform_impl(cow_string &str)
{
    const std::size_t size = str.length();
    char *input = str.modifiable_data();

    std::size_t i = 0;
#if defined(DDWAF_BYTE_SCAN_VECTOR)
    using byte_scan::bytes16;

    const auto case_bit = bytes16::splat(0x20);
    const auto to_lower = [&](std::size_t pos) {
        const auto data = bytes16::load(input + pos);
        // Uppercase letters only differ from their lowercase counterpart in
        // the 0x20 bit, which they don't have set
        (data | (is_upper::match(data) & case_bit)).store(input + pos);
    };

    if (size >= bytes16::size) {
        for (; i + bytes16::size <= size; i += bytes16::size) { to_lower(i); }

        if (i < size) {
            // The last block overlaps with the previous one, which is fine as
            // lowercasing is idempotent
            to_lower(size - bytes16::size);
        }
        return true;
    }
#endif

    for (; i < size; ++i) { input[i] = ddwaf::tolower(input[i]); }

    return true;
}

} // namespace ddwaf::transformer
