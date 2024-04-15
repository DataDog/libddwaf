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

inline sql_flavour sql_flavour_from_type(std::string_view type)
{
    if (type == "mysql" || type == "mysql2") {
        return sql_flavour::mysql;
    }
    if (type == "postgresql") {
        return sql_flavour::postgresql;
    }
    if (type == "sqlite") {
        return sql_flavour::sqlite;
    }
    if (type == "oracle") {
        return sql_flavour::oracle;
    }
    if (type == "doctrine") {
        return sql_flavour::doctrine;
    }
    if (type == "hsqldb") {
        return sql_flavour::hsqldb;
    }
    return sql_flavour::generic;
}

inline std::ostream &operator<<(std::ostream &os, sql_token_type type)
{
    switch (type) {
    case sql_token_type::command:
        os << "command";
        break;
    case sql_token_type::identifier:
        os << "identifier";
        break;
    case sql_token_type::number:
        os << "number";
        break;
    case sql_token_type::string:
        os << "string";
        break;
    case sql_token_type::single_quoted_string:
        os << "single_quoted_string";
        break;
    case sql_token_type::double_quoted_string:
        os << "double_quoted_string";
        break;
    case sql_token_type::back_quoted_string:
        os << "back_quoted_string";
        break;
    case sql_token_type::whitespace:
        os << "whitespace";
        break;
    case sql_token_type::asterisk:
        os << "asterisk";
        break;
    case sql_token_type::eol_comment:
        os << "eol_comment";
        break;
    case sql_token_type::parenthesis_open:
        os << "parenthesis_open";
        break;
    case sql_token_type::parenthesis_close:
        os << "parenthesis_close";
        break;
    case sql_token_type::comma:
        os << "comma";
        break;
    case sql_token_type::questionmark:
        os << "questionmark";
        break;
    case sql_token_type::label:
        os << "label";
        break;
    case sql_token_type::dot:
        os << "dot";
        break;
    case sql_token_type::query_end:
        os << "query_end";
        break;
    case sql_token_type::binary_operator:
        os << "binary_operator";
        break;
    case sql_token_type::bitwise_operator:
        os << "bitwise_operator";
        break;
    case sql_token_type::inline_comment:
        os << "inline_comment";
        break;
    }
    return os;
}

class sql_tokenizer {
public:
    explicit sql_tokenizer(std::string_view str);

    std::vector<sql_token> tokenize();

    void tokenize_command_operator_or_identifier();
    void tokenize_string(char quote);
    void tokenize_inline_comment_or_operator();
    void tokenize_eol_comment();
    void tokenize_eol_comment_operator_or_number();
    void tokenize_operator_or_number();
    bool tokenize_number();

protected:
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
        advance(size);
    }

    std::string_view buffer_;
    std::size_t idx_{0};
    std::vector<sql_token> tokens_{};
};

} // namespace ddwaf
