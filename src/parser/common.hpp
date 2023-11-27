// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <optional>
#include <string>

#include "exception.hpp"
#include "parameter.hpp"
#include "transformer/base.hpp"

namespace ddwaf::parser {

template <typename T, typename Key = std::string> T at(const parameter::map &map, const Key &key)
{
    try {
        return static_cast<T>(map.at(key));
    } catch (const std::out_of_range &) {
        throw missing_key(std::string(key));
    } catch (const bad_cast &e) {
        throw invalid_type(std::string(key), e);
    }
}

template <typename T, typename Key>
T at(const parameter::map &map, const Key &key, const T &default_)
{
    try {
        auto it = map.find(key);
        return it == map.end() ? default_ : static_cast<T>(it->second);
    } catch (const bad_cast &e) {
        throw invalid_type(std::string(key), e);
    }
}

std::optional<transformer_id> transformer_from_string(std::string_view str);

} // namespace ddwaf::parser
