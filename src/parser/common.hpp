// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <exception.hpp>
#include <parameter.hpp>
#include <string>

namespace ddwaf::parser {
template <typename T> T at(parameter::map &map, const std::string &key)
{
    try {
        return map.at(key);
    } catch (const std::out_of_range &) {
        throw missing_key(key);
    } catch (const bad_cast &e) {
        throw invalid_type(key, e);
    }
}

template <typename T> T at(parameter::map &map, const std::string &key, const T &default_)
{
    try {
        auto it = map.find(key);
        return it == map.end() ? default_ : it->second;
    } catch (const bad_cast &e) {
        throw invalid_type(key, e);
    }
}

} // namespace ddwaf::parser
