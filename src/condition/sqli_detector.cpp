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
#include <variant>

using namespace std::literals;

namespace ddwaf {

namespace {

constexpr const auto &npos = std::string_view::npos;

enum class sqli_error {
    none,
    invalid_sql,
};

using matched_param = std::pair<std::string, std::vector<std::string>>;
using sqli_result = std::variant<sqli_error, matched_param, std::monostate>;

bool contains_harmful_tokens(const std::vector<sql_token> &tokens)
{
    for (auto token : tokens) {
        auto t = token.type;
        if (t != sql_token_type::comma && t != sql_token_type::parenthesis_close &&
            t != sql_token_type::parenthesis_open && t != sql_token_type::number &&
            t != sql_token_type::hex && t != sql_token_type::single_quoted_string &&
            t != sql_token_type::double_quoted_string) {
            return true;
        }
    }
    return false;
}

std::span<sql_token> get_consecutive_tokens(
    std::vector<sql_token> &resource_tokens, std::size_t begin, std::size_t end)
{
    std::size_t index_begin = std::numeric_limits<std::size_t>::max();
    std::size_t index_end = 0;
    for (std::size_t i = 0; i < resource_tokens.size(); ++i) {
        const auto &rtoken = resource_tokens[i];
        auto rtoken_end = rtoken.index + rtoken.str.size();
        if (rtoken_end > begin) {
            if (rtoken.index < end) {
                if (i < index_begin) {
                    index_begin = i;
                }

                if (i > index_end || i == (resource_tokens.size() - 1)) {
                    index_end = i;
                }
            } else {
                break;
            }
        }
    }

    if (index_begin > index_end) {
        return {};
    }

    return std::span<sql_token>{&resource_tokens[index_begin], &resource_tokens[index_end]};
}

sqli_result sqli_impl(std::string_view resource, std::vector<sql_token> &resource_tokens,
    const ddwaf_object &params, sql_flavour flavour,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
    ddwaf::timer &deadline)
{
    static constexpr std::size_t min_str_len = 5;
    static constexpr std::size_t min_token_count = 4;

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
        std::size_t param_index = resource.find(value);
        if (param_index == npos) {
            continue;
        }

        if (resource_tokens.empty()) {
            resource_tokens = sql_tokenize(resource, flavour);
            if (resource_tokens.empty()) {
                return sqli_error::invalid_sql;
            }
        }

        auto consecutive_tokens =
            get_consecutive_tokens(resource_tokens, param_index, param_index + value.size());
        if (consecutive_tokens.size() < min_token_count) {
            continue;
        }

        if (contains_harmful_tokens(resource_tokens)) {
            return matched_param{std::string(value), it.get_current_path()};
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

    std::vector<sql_token> resource_tokens;
    /* // TODO only tokenize if there's a potential injection*/

    for (const auto &param : params) {
        auto res = sqli_impl(
            sql.value, resource_tokens, *param.value, flavour, objects_excluded, limits_, deadline);
        if (std::holds_alternative<matched_param>(res)) {
            std::vector<std::string> sql_kp{sql.key_path.begin(), sql.key_path.end()};
            bool ephemeral = sql.ephemeral || param.ephemeral;

            auto &[highlight, param_kp] = std::get<matched_param>(res);
            cache.match =
                condition_match{{{"resource"sv, std::string{sql.value}, sql.address, sql_kp},
                                    {"params"sv, highlight, param.address, param_kp},
                                    {"db_type"sv, std::string{db_type.value}, db_type.address, {}}},
                    {std::move(highlight)}, "sqli_detector", {}, ephemeral};

            return {true, sql.ephemeral || param.ephemeral};
        }

        if (std::holds_alternative<std::monostate>(res)) {
            continue;
        }

        if (std::holds_alternative<sqli_error>(res)) {
            // The only error for now is returned when the resource couldn't be
            // parsed, we don't do anything specific for now other than stopping
            // the evaluation of the parameters
            break;
        }
    }

    return {};
}

} // namespace ddwaf
