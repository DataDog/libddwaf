// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "utils.hpp"
#include <iostream>
#include <memory>
#include <ostream>
#include <re2/re2.h>
#include <string_view>
#include <vector>

namespace ddwaf {

enum class sql_dialect { generic, mysql, postgresql, oracle, sqlite, hsqldb, doctrine };

enum class sql_token_type {
    unknown,
    command,
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
    label,
    dot,
    query_end,
    binary_operator,
    bitwise_operator,
    inline_comment,
    array_open,
    array_close,
};

struct sql_token {
    sql_token_type type{sql_token_type::unknown};
    std::string_view str;
    std::size_t index{};
};

sql_dialect sql_dialect_from_type(std::string_view type);
std::ostream &operator<<(std::ostream &os, sql_token_type type);

template <typename T> class sql_tokenizer {
public:
    explicit sql_tokenizer(std::string_view str) : buffer_(str) {}

    std::vector<sql_token> tokenize() { return static_cast<T *>(this)->tokenize_impl(); }

protected:
    [[nodiscard]] char peek() const
    {
        if (idx_ >= buffer_.size()) {
            [[unlikely]] return '\0';
        }
        return buffer_[idx_];
    }
    [[nodiscard]] char prev(std::size_t offset = 1) const
    {
        if (idx_ < offset) {
            [[unlikely]] return '\0';
        }
        return buffer_[idx_ - 1];
    }

    bool advance(std::size_t offset = 1) { return (idx_ += offset) < buffer_.size(); }

    [[nodiscard]] char next(std::size_t offset = 1)
    {
        if ((idx_ + offset) >= buffer_.size()) {
            [[unlikely]] return '\0';
        }
        return buffer_[idx_ + offset];
    }

    bool eof() { return idx_ >= buffer_.size(); }

    [[nodiscard]] std::size_t index() const { return idx_; }

    std::string_view substr(std::size_t start, std::size_t size = std::string_view::npos)
    {
        return buffer_.substr(start, size);
    }

    std::string_view substr() { return buffer_.substr(idx_); }

    void add_token(sql_token_type type, std::size_t size = 1)
    {
        sql_token token;
        token.index = index();
        token.type = type;
        token.str = substr(token.index, size);
        tokens_.emplace_back(token);
        advance(size - 1);
    }

    optional_ref<sql_token> last_token()
    {
        if (tokens_.empty()) {
            return {};
        }
        return tokens_.back();
    }

    void tokenize_string(char quote, sql_token_type type)
    {
        sql_token token;
        token.index = index();
        token.type = type;

        unsigned slash_count = 0;
        while (advance()) {
            if (peek() == '\\') {
                // Count consecutive backslashes
                slash_count = (slash_count + 1) % 2;
            } else if (slash_count > 0) {
                slash_count = 0;
            } else if (peek() == quote && slash_count == 0) {
                break;
            }
        }
        token.str = substr(token.index, index() - token.index + 1);
        tokens_.emplace_back(token);
    }

    std::string_view buffer_;
    std::size_t idx_{0};
    std::vector<sql_token> tokens_{};
};

} // namespace ddwaf
