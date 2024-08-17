// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2024 Datadog, Inc.

// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <memory>

#include "matcher/equals.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/greater_than.hpp"
#include "matcher/ip_match.hpp"
#include "matcher/is_sqli.hpp"
#include "matcher/is_xss.hpp"
#include "matcher/phrase_match.hpp"
#include "matcher/regex_match.hpp"
#include "parameter.hpp"
#include "parser/common.hpp"

namespace ddwaf::parser::v2 {

std::pair<std::string, std::unique_ptr<matcher::base>> parse_matcher(
    std::string_view name, const parameter::map &params)
{
    parameter::map options;
    std::unique_ptr<matcher::base> matcher;
    std::string rule_data_id;

    if (name == "phrase_match") {
        auto list = at<parameter::vector>(params, "list");
        options = at<parameter::map>(params, "options", options);
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

        matcher = std::make_unique<matcher::phrase_match>(patterns, lengths, word_boundary);
    } else if (name == "match_regex") {
        auto regex = at<std::string>(params, "regex");
        options = at<parameter::map>(params, "options", options);

        auto case_sensitive = at<bool>(options, "case_sensitive", false);
        auto min_length = at<int64_t>(options, "min_length", 0);
        if (min_length < 0) {
            throw ddwaf::parsing_error("min_length is a negative number");
        }

        matcher = std::make_unique<matcher::regex_match>(regex, min_length, case_sensitive);
    } else if (name == "is_xss") {
        matcher = std::make_unique<matcher::is_xss>();
    } else if (name == "is_sqli") {
        matcher = std::make_unique<matcher::is_sqli>();
    } else if (name == "ip_match") {
        auto it = params.find("list");
        if (it == params.end()) {
            rule_data_id = at<std::string>(params, "data");
        } else {
            matcher = std::make_unique<matcher::ip_match>(
                static_cast<std::vector<std::string_view>>(it->second));
        }
    } else if (name == "exact_match") {
        auto it = params.find("list");
        if (it == params.end()) {
            rule_data_id = at<std::string>(params, "data");
        } else {
            matcher = std::make_unique<matcher::exact_match>(
                static_cast<std::vector<std::string>>(it->second));
        }
    } else if (name == "equals") {
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
    } else if (name == "greater_than") {
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

    } else {
        throw ddwaf::parsing_error("unknown matcher: " + std::string(name));
    }

    return {std::move(rule_data_id), std::move(matcher)};
}

} // namespace ddwaf::parser::v2
