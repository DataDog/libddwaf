// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <libinjection.h>
#include <string_view>
#include <utility>

#include "dynamic_string.hpp"
#include "matcher/is_xss.hpp"

namespace ddwaf::matcher {

std::pair<bool, dynamic_string> is_xss::match_impl(std::string_view pattern)
{
    if (pattern.empty() || pattern.data() == nullptr ||
        libinjection_xss(pattern.data(), pattern.size()) == 0) {
        return {false, {}};
    }

    return {true, {}};
}

} // namespace ddwaf::matcher
