// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule_processor/is_xss.hpp>
#include <libinjection.h>
#include <utils.h>

namespace ddwaf::rule_processor
{

std::optional<event::match> is_xss::match(std::string_view str) const
{
    if (str.empty()) {
        return {};
    }

    if (!libinjection_xss(str.data(), str.size())) {
        return {};
    }

    return make_event(str, str);
}

}
