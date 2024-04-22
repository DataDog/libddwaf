// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <ostream>
#include <re2/re2.h>
#include <string_view>
#include <vector>

#include "tokenizer/sql_base.hpp"

namespace ddwaf {

class generic_sql_tokenizer : public sql_tokenizer<generic_sql_tokenizer> {
public:
    explicit generic_sql_tokenizer(std::string_view str);

protected:
    std::vector<sql_token> tokenize_impl();

    void tokenize_command_operator_or_identifier();
    void tokenize_inline_comment_or_operator();
    void tokenize_eol_comment();
    void tokenize_eol_comment_operator_or_number();
    void tokenize_operator_or_number();

    friend class sql_tokenizer<generic_sql_tokenizer>;
};

} // namespace ddwaf
