// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2024 Datadog, Inc.

// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "configuration/common/common.hpp"
#include "configuration/common/matcher_parser.hpp" // IWYU pragma: keep
#include "configuration/common/parser_exception.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "ddwaf.h"
#include "matcher/base.hpp"
#include "matcher/equals.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/greater_than.hpp"
#include "matcher/ip_match.hpp"
#include "matcher/is_sqli.hpp"
#include "matcher/is_xss.hpp"
#include "matcher/lower_than.hpp"
#include "matcher/phrase_match.hpp"
#include "matcher/regex_match.hpp"

namespace ddwaf {

template <>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher<matcher::phrase_match>(
    const raw_configuration::map &params)
{
    raw_configuration::map options;

    auto list = at<raw_configuration::vector>(params, "list");
    options = at<raw_configuration::map>(params, "options", options);
    auto word_boundary = at<bool>(options, "enforce_word_boundary", false);

    std::vector<const char *> patterns;
    std::vector<uint32_t> lengths;

    patterns.reserve(list.size());
    lengths.reserve(list.size());

    for (auto &pattern : list) {
        if (pattern.type != DDWAF_OBJ_STRING) {
            throw ddwaf::parsing_error("phrase_match list item not a string");
        }

        patterns.push_back(pattern.stringValue);
        lengths.push_back((uint32_t)pattern.nbEntries);
    }

    return {
        std::string{}, std::make_unique<matcher::phrase_match>(patterns, lengths, word_boundary)};
}

template <>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher<matcher::regex_match>(
    const raw_configuration::map &params)
{
    raw_configuration::map options;

    auto regex = at<std::string>(params, "regex");
    options = at<raw_configuration::map>(params, "options", options);

    auto case_sensitive = at<bool>(options, "case_sensitive", false);
    auto min_length = at<int64_t>(options, "min_length", 0);
    if (min_length < 0) {
        throw ddwaf::parsing_error("min_length is a negative number");
    }

    return {
        std::string{}, std::make_unique<matcher::regex_match>(regex, min_length, case_sensitive)};
}

template <>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher<matcher::is_xss>(
    const raw_configuration::map & /*params*/)
{
    return {std::string{}, std::make_unique<matcher::is_xss>()};
}

template <>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher<matcher::is_sqli>(
    const raw_configuration::map & /*params*/)
{
    return {std::string{}, std::make_unique<matcher::is_sqli>()};
}

template <>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher<matcher::ip_match>(
    const raw_configuration::map &params)
{
    std::unique_ptr<matcher::base> matcher;
    std::string rule_data_id;

    auto it = params.find("list");
    if (it == params.end()) {
        rule_data_id = at<std::string>(params, "data");
    } else {
        matcher = std::make_unique<matcher::ip_match>(
            static_cast<std::vector<std::string_view>>(it->second));
    }

    return {std::move(rule_data_id), std::move(matcher)};
}

template <>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher<matcher::exact_match>(
    const raw_configuration::map &params)
{
    std::unique_ptr<matcher::base> matcher;
    std::string rule_data_id;

    auto it = params.find("list");
    if (it == params.end()) {
        rule_data_id = at<std::string>(params, "data");
    } else {
        matcher = std::make_unique<matcher::exact_match>(
            static_cast<std::vector<std::string>>(it->second));
    }

    return {std::move(rule_data_id), std::move(matcher)};
}

template <>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher<matcher::equals<>>(
    const raw_configuration::map &params)
{
    std::unique_ptr<matcher::base> matcher;
    auto value_type = at<std::string>(params, "type");
    if (value_type == "string") {
        auto value = at<std::string>(params, "value");
        matcher = std::make_unique<matcher::equals<std::string>>(std::move(value));
    } else if (value_type == "boolean") {
        auto value = at<bool>(params, "value");
        matcher = std::make_unique<matcher::equals<bool>>(value);
    } else if (value_type == "unsigned") {
        auto value = at<uint64_t>(params, "value");
        matcher = std::make_unique<matcher::equals<uint64_t>>(value);
    } else if (value_type == "signed") {
        auto value = at<int64_t>(params, "value");
        matcher = std::make_unique<matcher::equals<int64_t>>(value);
    } else if (value_type == "float") {
        auto value = at<double>(params, "value");
        auto delta = at<double>(params, "delta", 0.01);
        matcher = std::make_unique<matcher::equals<double>>(value, delta);
    } else {
        throw ddwaf::parsing_error("invalid type for matcher equals " + value_type);
    }
    return {std::string{}, std::move(matcher)};
}

template <>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher<matcher::lower_than<>>(
    const raw_configuration::map &params)
{
    std::unique_ptr<matcher::base> matcher;
    auto value_type = at<std::string>(params, "type");
    if (value_type == "unsigned") {
        auto value = at<uint64_t>(params, "value");
        matcher = std::make_unique<matcher::lower_than<uint64_t>>(value);
    } else if (value_type == "signed") {
        auto value = at<int64_t>(params, "value");
        matcher = std::make_unique<matcher::lower_than<int64_t>>(value);
    } else if (value_type == "float") {
        auto value = at<double>(params, "value");
        matcher = std::make_unique<matcher::lower_than<double>>(value);
    } else {
        throw ddwaf::parsing_error("invalid type for matcher lower_than " + value_type);
    }

    return {std::string{}, std::move(matcher)};
}

template <>
std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher<matcher::greater_than<>>(
    const raw_configuration::map &params)
{
    std::unique_ptr<matcher::base> matcher;

    auto value_type = at<std::string>(params, "type");
    if (value_type == "unsigned") {
        auto value = at<uint64_t>(params, "value");
        matcher = std::make_unique<matcher::greater_than<uint64_t>>(value);
    } else if (value_type == "signed") {
        auto value = at<int64_t>(params, "value");
        matcher = std::make_unique<matcher::greater_than<int64_t>>(value);
    } else if (value_type == "float") {
        auto value = at<double>(params, "value");
        matcher = std::make_unique<matcher::greater_than<double>>(value);
    } else {
        throw ddwaf::parsing_error("invalid type for matcher greater_than " + value_type);
    }

    return {std::string{}, std::move(matcher)};
}

} // namespace ddwaf
