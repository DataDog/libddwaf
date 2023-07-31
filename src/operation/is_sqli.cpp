// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <array>
#include <libinjection.h>
#include <operation/is_sqli.hpp>
#include <utils.hpp>

namespace ddwaf::operation {

std::optional<event::match> is_sqli::match(std::string_view pattern) const
{
    if (pattern.empty() || pattern.data() == nullptr) {
        return std::nullopt;
    }

    // NOLINTNEXTLINE(hicpp-avoid-c-arrays)
    std::array<char, fingerprint_length> fingerprint{0};
    if (libinjection_sqli(pattern.data(), pattern.size(), fingerprint.data()) == 0) {
        return std::nullopt;
    }

    return make_event(pattern, fingerprint.data());
}

} // namespace ddwaf::operation
