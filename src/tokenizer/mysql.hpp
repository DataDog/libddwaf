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

class mysql_tokenizer : public sql_tokenizer<mysql_tokenizer> {
public:
    explicit mysql_tokenizer(std::string_view str);

protected:
    std::vector<sql_token> tokenize_impl();

    void tokenize_command_operator_or_identifier();
    void tokenize_inline_comment_or_operator();
    void tokenize_eol_comment();
    void tokenize_eol_comment_operator_or_number();
    void tokenize_operator_or_number();
    void tokenize_number_or_identifier();
    void tokenize_variable();

    friend class sql_tokenizer<mysql_tokenizer>;
};

} // namespace ddwaf
