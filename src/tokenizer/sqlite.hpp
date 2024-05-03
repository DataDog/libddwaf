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

class sqlite_tokenizer : public sql_tokenizer<sqlite_tokenizer> {
public:
    explicit sqlite_tokenizer(
        std::string_view str, std::unordered_set<sql_token_type> skip_tokens = {});

protected:
    std::vector<sql_token> tokenize_impl();

    std::string_view extract_conforming_string(char quote);
    void tokenize_conforming_string(char quote, sql_token_type type);
    void tokenize_keyword_operator_or_identifier();
    void tokenize_inline_comment_or_operator();
    void tokenize_eol_comment();
    void tokenize_eol_comment_or_operator_or_number();
    void tokenize_operator_or_number();

    friend class sql_tokenizer<sqlite_tokenizer>;
};

} // namespace ddwaf
