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

namespace ddwaf {

enum class sql_flavour { generic, mysql, postgresql, oracle, sqlite, hsqldb, doctrine };

enum class sql_token_type {
    command,
    identifier,
    number,
    string,
    single_quoted_string,
    double_quoted_string,
    back_quoted_string,
    whitespace,
    asterisk,
    eol_comment,
    parenthesis_open,
    parenthesis_close,
    comma,
    questionmark,
    label,
    dot,
    query_end,
    binary_operator,
    bitwise_operator,
    inline_comment,
};

struct sql_token {
    sql_token_type type;
    std::string_view str;
    std::size_t index;
};

sql_flavour sql_flavour_from_type(std::string_view type);
std::ostream &operator<<(std::ostream &os, sql_token_type type);

class sql_tokenizer {
public:
    explicit sql_tokenizer(std::string_view str) : buffer_(str) {}

    std::vector<sql_token> tokenize();

protected:
    void tokenize_command_operator_or_identifier();
    void tokenize_string(char quote, sql_token_type type);
    void tokenize_inline_comment_or_operator();
    void tokenize_eol_comment();
    void tokenize_eol_comment_operator_or_number();
    void tokenize_operator_or_number();
    void tokenize_number();

    char peek() const
    {
        if (idx_ >= buffer_.size()) {
            [[unlikely]] return '\0';
        }
        return buffer_[idx_];
    }
    char prev() const
    {
        if (idx_ == 0) {
            [[unlikely]] return '\0';
        }
        return buffer_[idx_ - 1];
    }

    bool advance(std::size_t offset = 1) { return (idx_ += offset) < buffer_.size(); }

    char next(std::size_t offset = 1)
    {
        if ((idx_ + offset) >= buffer_.size()) {
            [[unlikely]] return '\0';
        }
        return buffer_[idx_ + offset];
    }

    bool eof() { return idx_ >= buffer_.size(); }

    std::size_t index() { return idx_; }

    std::string_view substr(std::size_t start, std::size_t size = std::string_view::npos)
    {
        return buffer_.substr(start, size);
    }

    void add_token(sql_token_type type, std::size_t size = 1)
    {
        sql_token token;
        token.index = index();
        token.type = type;
        token.str = substr(token.index, size);
        tokens_.emplace_back(token);
        advance(size - 1);
    }

    std::string_view buffer_;
    std::size_t idx_{0};
    std::vector<sql_token> tokens_{};
};

} // namespace ddwaf
