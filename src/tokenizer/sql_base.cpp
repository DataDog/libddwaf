// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "tokenizer/sql_base.hpp"
#include "tokenizer/generic_sql.hpp"
#include "tokenizer/mysql.hpp"
#include "tokenizer/pgsql.hpp"
#include "tokenizer/sqlite.hpp"

#include <iostream>

namespace ddwaf {
namespace {
// Hexadecimal, octal, decimal or floating point
constexpr std::string_view number_regex_str =
    R"((?i)^(0x[0-9a-fA-F]+|[-+]*(?:[0-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)(?:\b|\s|$))";

re2::RE2 number_regex{number_regex_str};
} // namespace

sql_dialect sql_dialect_from_type(std::string_view type)
{
    if (string_iequals(type, "mysql") || string_iequals(type, "mysql2")) {
        return sql_dialect::mysql;
    }
    if (string_iequals(type, "postgresql") || string_iequals(type, "pgsql")) {
        return sql_dialect::pgsql;
    }
    if (string_iequals(type, "sqlite")) {
        return sql_dialect::sqlite;
    }
    if (string_iequals(type, "oracle")) {
        return sql_dialect::oracle;
    }
    if (string_iequals(type, "doctrine")) {
        return sql_dialect::doctrine;
    }
    if (string_iequals(type, "hsqldb")) {
        return sql_dialect::hsqldb;
    }
    return sql_dialect::generic;
}

std::string_view sql_dialect_to_string(sql_dialect dialect)
{
    switch (dialect) {
    case sql_dialect::mysql:
        return "mysql";
    case sql_dialect::pgsql:
        return "pgsql";
    case sql_dialect::sqlite:
        return "sqlite";
    case sql_dialect::oracle:
        return "oracle";
    case sql_dialect::doctrine:
        return "doctrine";
    case sql_dialect::hsqldb:
        return "hsqldb";
    case sql_dialect::generic:
    default:
        return "generic";
    }
}

std::ostream &operator<<(std::ostream &os, sql_dialect dialect)
{
    os << sql_dialect_to_string(dialect);
    return os;
}

std::ostream &operator<<(std::ostream &os, sql_token_type type)
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
    case sql_token_type::dollar_quoted_string:
        os << "dollar_quoted_string";
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
    case sql_token_type::colon:
        os << "colon";
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
    case sql_token_type::array_open:
        os << "array_open";
        break;
    case sql_token_type::array_close:
        os << "array_close";
        break;
    case sql_token_type::curly_brace_open:
        os << "curly_brace_open";
        break;
    case sql_token_type::curly_brace_close:
        os << "curly_brace_close";
        break;
    case sql_token_type::unknown:
    default:
        os << "unknown";
        break;
    }
    return os;
}

template <typename T>
sql_tokenizer<T>::sql_tokenizer(
    std::string_view str, std::unordered_set<sql_token_type> skip_tokens)
    : buffer_(str), skip_tokens_(std::move(skip_tokens))
{
    if (!number_regex.ok()) {
        throw std::runtime_error("sql number regex not valid: " + number_regex.error_arg());
    }
}

template <typename T> std::string_view sql_tokenizer<T>::extract_string(char quote)
{
    auto begin = index();
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
    return substr(begin, index() - begin + 1);
}

template <typename T> std::string_view sql_tokenizer<T>::extract_number()
{
    auto str = substr();
    re2::StringPiece number;
    const re2::StringPiece ref(str.data(), str.size());
    if (re2::RE2::PartialMatch(ref, number_regex, &number)) {
        if (!number.empty()) {
            return {number.data(), number.size()};
        }
    }
    return {};
}

template <typename T> void sql_tokenizer<T>::tokenize_string(char quote, sql_token_type type)
{
    sql_token token;
    token.index = index();
    token.type = type;
    token.str = extract_string(quote);
    emplace_token(token);
}

template <typename T> void sql_tokenizer<T>::tokenize_number()
{
    sql_token token;
    token.str = extract_number();
    if (!token.str.empty()) {
        token.index = index();
        token.type = sql_token_type::number;
        emplace_token(token);
        advance(token.str.size() - 1);
    }
}

template class sql_tokenizer<pgsql_tokenizer>;
template class sql_tokenizer<mysql_tokenizer>;
template class sql_tokenizer<sqlite_tokenizer>;
template class sql_tokenizer<generic_sql_tokenizer>;

} // namespace ddwaf
