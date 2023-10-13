// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <libinjection.h>

#include "matcher/is_sqli.hpp"
#include "utils.hpp"

namespace ddwaf::matcher {

std::pair<bool, std::string> is_sqli::match_impl(std::string_view pattern)
{
    if (pattern.empty() || pattern.data() == nullptr) {
        return {false, {}};
    }

    // NOLINTNEXTLINE(hicpp-avoid-c-arrays)
    std::array<char, fingerprint_length> fingerprint{0};
    if (libinjection_sqli(pattern.data(), pattern.size(), fingerprint.data()) == 0) {
        return {false, {}};
    }

    return {true, fingerprint.data()};
}

} // namespace ddwaf::matcher
