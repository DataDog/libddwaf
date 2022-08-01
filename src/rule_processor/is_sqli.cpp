// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule_processor/is_sqli.hpp>
#include <libinjection.h>
#include <utils.h>

namespace ddwaf::rule_processor
{

std::optional<event::match> is_sqli::match(std::string_view str) const
{
    if (str.empty()) {
        return {};
    }
    //The mandated length is 8
    char fingerprint[16] = {0};
    if (!libinjection_sqli(str.data(), str.size(), fingerprint)) {
        return {};
    }

    return event::match{std::string(str), fingerprint, name(), to_string(), {}, {}};
}

}
