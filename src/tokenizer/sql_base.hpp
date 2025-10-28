// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "fmt/core.h"
#include "tokenizer/base.hpp"
#include <cstdint>
#include <fmt/format.h>
#include <ostream>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace ddwaf {

enum class sql_dialect : uint8_t { generic, mysql, pgsql, oracle, sqlite, hsqldb, doctrine };

enum class sql_token_type : uint8_t {
    unknown,
    keyword,
    identifier,
    number,
    string,
    single_quoted_string,
    double_quoted_string,
    back_quoted_string,
    dollar_quoted_string,
    whitespace,
    asterisk,
    eol_comment,
    parenthesis_open,
    parenthesis_close,
    comma,
    questionmark,
    colon,
    dot,
    query_end,
    binary_operator,
    bitwise_operator,
    inline_comment,
    array_open,
    array_close,
    curly_brace_open,
    curly_brace_close,
};

using sql_token = base_token<sql_token_type>;

sql_dialect sql_dialect_from_type(std::string_view type);
std::string_view sql_dialect_to_string(sql_dialect dialect);
std::ostream &operator<<(std::ostream &os, sql_dialect dialect);

template <> struct fmt::formatter<sql_dialect> : fmt::formatter<std::string_view> {
    // Use the parse method from the base class formatter
    template <typename FormatContext> auto format(sql_dialect d, FormatContext &ctx)
    {
        return fmt::formatter<std::string_view>::format(sql_dialect_to_string(d), ctx);
    }
};

std::ostream &operator<<(std::ostream &os, sql_token_type type);

template <typename T> class sql_tokenizer : protected base_tokenizer<sql_token_type> {
public:
    explicit sql_tokenizer(
        std::string_view str, std::unordered_set<sql_token_type> skip_tokens = {});

    std::vector<sql_token> tokenize() { return static_cast<T *>(this)->tokenize_impl(); }

    static bool initialise_regexes();

protected:
    std::string_view extract_unescaped_string(char quote);
    std::string_view extract_conforming_string(char quote);
    std::string_view extract_escaped_string(char quote);
    std::string_view extract_number();

    void tokenize_unescaped_string(char quote, sql_token_type type);
    void tokenize_conforming_string(char quote, sql_token_type type);
    void tokenize_escaped_string(char quote, sql_token_type type);
    void tokenize_number();
    // Assumes the first character is + or -
    void tokenize_operator_or_number();
};

} // namespace ddwaf
