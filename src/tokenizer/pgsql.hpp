// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <re2/re2.h>
#include <string_view>
#include <vector>

#include "tokenizer/sql_base.hpp"

namespace ddwaf {

class pgsql_tokenizer : public sql_tokenizer<pgsql_tokenizer> {
public:
    explicit pgsql_tokenizer(
        std::string_view str, std::unordered_set<sql_token_type> skip_tokens = {});

    static bool initialise_regexes();

protected:
    std::vector<sql_token> tokenize_impl();

    void tokenize_string_keyword_operator_or_identifier();
    void tokenize_inline_comment_or_operator();
    void tokenize_eol_comment();
    void tokenize_eol_comment_or_operator_or_number();
    void tokenize_dollar_quoted_string();
    void tokenize_dollar_string_or_identifier();

    friend class sql_tokenizer<pgsql_tokenizer>;
};

} // namespace ddwaf
