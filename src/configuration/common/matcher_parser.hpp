// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <utility>

#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "matcher/base.hpp"
#include "matcher/equals.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/greater_than.hpp"
#include "matcher/hidden_ascii_match.hpp"
#include "matcher/ip_match.hpp"
#include "matcher/is_sqli.hpp"
#include "matcher/is_xss.hpp"
#include "matcher/lower_than.hpp"
#include "matcher/phrase_match.hpp"
#include "matcher/regex_match.hpp"
#include "matcher/regex_match_with_checksum.hpp"

namespace ddwaf {

template <typename Matcher>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher(
    const raw_configuration::map &params);

template <typename Matcher, typename... Rest>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher(
    std::string_view name, const raw_configuration::map &params)
{
    if (Matcher::matcher_name == name) {
        return parse_matcher<Matcher>(params);
    }

    if constexpr (sizeof...(Rest) > 0) {
        return parse_matcher<Rest...>(name, params);
    } else {
        throw unknown_operator(name);
    }
}

inline std::pair<std::string, std::unique_ptr<matcher::base>> parse_any_matcher(
    std::string_view name, const raw_configuration::map &params)
{
    return parse_matcher<matcher::equals<>, matcher::exact_match, matcher::greater_than<>,
        matcher::ip_match, matcher::is_sqli, matcher::is_xss, matcher::lower_than<>,
        matcher::phrase_match, matcher::regex_match, matcher::regex_match_with_checksum,
        matcher::hidden_ascii_match>(name, params);
}

} // namespace ddwaf
