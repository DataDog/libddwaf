// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/structured_condition.hpp"
#include "tokenizer/sql_base.hpp"

namespace ddwaf {

class sqli_detector : public base_impl<sqli_detector> {
public:
    static constexpr std::array<std::string_view, 3> param_names{"resource", "params", "db_type"};

    explicit sqli_detector(std::vector<parameter_definition> args, const object_limits &limits = {})
        : base_impl<sqli_detector>(std::move(args), limits)
    {}

protected:
    [[nodiscard]] eval_result eval_impl(const unary_argument<std::string_view> &sql,
        const variadic_argument<const ddwaf_object *> &params,
        const unary_argument<std::string_view> &db_type, condition_cache &cache,
        const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const;

    friend class base_impl<sqli_detector>;
};

namespace internal {
// Exposed for testing purposes
std::pair<std::span<sql_token>, std::size_t> get_consecutive_tokens(
    std::vector<sql_token> &resource_tokens, std::size_t begin, std::size_t end);

bool contains_harmful_tokens(std::span<sql_token> tokens);

bool has_order_by_structure(std::span<sql_token> tokens);
bool is_benign_order_by_clause(const std::vector<sql_token> &resource_tokens,
    std::span<sql_token> param_tokens, std::size_t param_tokens_begin);

bool is_where_tautology(const std::vector<sql_token> &resource_tokens,
    std::span<sql_token> param_tokens, std::size_t param_tokens_begin);

bool is_query_comment(std::span<sql_token> tokens);

} // namespace internal

} // namespace ddwaf
