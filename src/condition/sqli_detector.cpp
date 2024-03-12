// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/sqli_detector.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "platform.hpp"
#include "sql_tokenizer.hpp"
#include "utils.hpp"
#include <iostream>

using namespace std::literals;

namespace ddwaf {

namespace {

using sqli_result = std::optional<std::pair<std::string, std::vector<std::string>>>;

sqli_result sqli_impl(const std::vector<sql_token> &resource_tokens, const ddwaf_object &params,
    sql_flavour flavour, const exclusion::object_set_ref &objects_excluded,
    const object_limits &limits, ddwaf::timer &deadline)
{
    static constexpr std::size_t min_str_len = 5;

    object::kv_iterator it(&params, {}, objects_excluded, limits);
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const ddwaf_object &param = *(*it);
        if (param.type != DDWAF_OBJ_STRING || param.nbEntries < min_str_len) {
            continue;
        }

        std::string_view value{param.stringValue, static_cast<std::size_t>(param.nbEntries)};
        std::cout << " -- Parsing parameter\n";
        auto params_tokens = sql_tokenize(value, flavour);
        if (params_tokens.empty()) {
            // if (params_tokens.size() < 2) {
            continue;
        }

        bool start_found = false;
        std::size_t i = 0;
        for (; i < resource_tokens.size(); ++i) {
            if (resource_tokens[i].type == params_tokens[0].type) {
                start_found = true;
                break;
            }
        }

        if (start_found && (i + params_tokens.size()) <= resource_tokens.size()) {
            bool all_equals = true;
            for (std::size_t j = 1; j < params_tokens.size(); ++j) {
                if (resource_tokens[i + j].type != params_tokens[j].type) {
                    all_equals = false;
                    break;
                }
            }

            if (all_equals) {
                return {{std::string(value), it.get_current_path()}};
            }
        }
    }

    return {};
}

} // namespace

[[nodiscard]] eval_result sqli_detector::eval_impl(const unary_argument<std::string_view> &sql,
    const variadic_argument<const ddwaf_object *> &params,
    const unary_argument<std::string_view> &db_type, condition_cache &cache,
    const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const
{
    auto flavour = sql_flavour_from_type(db_type.value);
    auto resource_tokens = sql_tokenize(sql.value, flavour);

    for (const auto &param : params) {
        auto res =
            sqli_impl(resource_tokens, *param.value, flavour, objects_excluded, limits_, deadline);
        if (res.has_value()) {
            std::vector<std::string> sql_kp{sql.key_path.begin(), sql.key_path.end()};
            bool ephemeral = sql.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = res.value();
            cache.match =
                condition_match{{{"resource"sv, std::string{sql.value}, sql.address, sql_kp},
                                    {"params"sv, highlight, param.address, param_kp},
                                    {"db_type"sv, std::string{db_type.value}, db_type.address, {}}},
                    {std::move(highlight)}, "sqli_detector", {}, ephemeral};

            return {true, sql.ephemeral || param.ephemeral};
        }
    }

    return {};
}

} // namespace ddwaf
