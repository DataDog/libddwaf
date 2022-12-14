// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <libinjection.h>
#include <rule_processor/is_xss.hpp>
#include <utils.h>

namespace ddwaf::rule_processor {

std::optional<event::match> is_xss::match(std::string_view pattern) const
{
    if (pattern.empty() || pattern.data() == nullptr) {
        return std::nullopt;
    }

    if (libinjection_xss(pattern.data(), pattern.size()) == 0) {
        return std::nullopt;
    }

    return make_event(pattern, {});
}

} // namespace ddwaf::rule_processor
