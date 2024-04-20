// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "tokenizer/pgsql.hpp"
#include "regex_utils.hpp"
#include "utils.hpp"

#include <iostream>

// TODO: Split the tokenizer into different dialects

namespace ddwaf {
namespace {
constexpr std::string_view identifier_regex_str =
    R"((?i)(?P<command>SELECT|FROM|WHERE|GROUP BY|OFFSET|LIMIT|HAVING|ORDER BY|ASC|DESC)\b|(?P<binary_operator>OR|XOR|AND|IN|BETWEEN|LIKE|REGEXP|SOUNDS LIKE|IS NULL|IS NOT NULL|NOT|IS|MOD|DIV)\b|(?P<identifier>[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*\b))";
constexpr std::string_view number_regex_str =
    R"((?i)(0x[0-9a-fA-F]+|[-+]*(?:[0-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b))";
constexpr std::string_view parameter_regex_str = R"(\$[0-9]+\b)";

auto identifier_regex = regex_init(identifier_regex_str);
auto number_regex = regex_init(number_regex_str);
auto parameter_regex = regex_init(parameter_regex_str);

std::string_view extract_number(std::string_view str)
{
    re2::StringPiece number;
    const re2::StringPiece ref(str.data(), str.size());
    if (re2::RE2::PartialMatch(ref, *number_regex, &number)) {
        if (!number.empty()) {
            return {number.data(), number.size()};
        }
    }
    return {};
}

} // namespace

void pgsql_tokenizer::tokenize_command_operator_or_identifier()
{
    sql_token token;
    token.index = index();

    auto remaining_str = substr(index());

    re2::StringPiece binary_op;
    re2::StringPiece command;
    re2::StringPiece ident;

    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, *identifier_regex, &command, &binary_op, &ident)) {
        // At least one of the strings will contain a match
        if (!binary_op.empty()) {
            token.type = sql_token_type::binary_operator;
            token.str = substr(token.index, binary_op.size());
            advance(token.str.size() - 1);
        } else if (!command.empty()) {
            token.type = sql_token_type::command;
            token.str = substr(token.index, command.size());
            advance(token.str.size() - 1);
        } else if (!ident.empty()) {
            token.type = sql_token_type::identifier;
            token.str = substr(token.index, ident.size());
            advance(token.str.size() - 1);
        }
        tokens_.emplace_back(token);
    }
}

void pgsql_tokenizer::tokenize_inline_comment_or_operator()
{
    // The first character is / so it can be a comment or a binary operator
    sql_token token;
    token.index = index();
    if (advance() && peek() == '*') {
        // Comment
        advance(); // Skip the '*' in prev()
        while (advance()) {
            if (prev() == '*' && peek() == '/') {
                break;
            }
        }
        token.str = substr(token.index, index() - token.index + 1);
        token.type = sql_token_type::inline_comment;
    } else {
        token.str = substr(token.index, 1);
        token.type = sql_token_type::binary_operator;
    }
    tokens_.emplace_back(token);
}

void pgsql_tokenizer::tokenize_number()
{
    sql_token token;
    token.index = index();
    token.type = sql_token_type::number;
    token.str = extract_number(substr(index()));
    if (!token.str.empty()) {
        tokens_.emplace_back(token);
    }
    advance(token.str.size() - 1);
}

void pgsql_tokenizer::tokenize_eol_comment()
{
    // Inline comment
    sql_token token;
    token.index = index();

    while (advance() && peek() != '\n') {}

    token.str = substr(token.index, index() - token.index);
    token.type = sql_token_type::eol_comment;
    tokens_.emplace_back(token);
}

void pgsql_tokenizer::tokenize_eol_comment_operator_or_number()
{
    auto n = next();
    if (n == '-') {
        tokenize_eol_comment();
        return;
    }

    if (n == '>') { // Match JSON operators ->> and ->
        add_token(sql_token_type::binary_operator, next(2) == '>' ? 3 : 2);
        return;
    }

    sql_token token;
    token.index = index();

    auto number_str = extract_number(substr(index()));
    if (!number_str.empty()) {
        token.type = sql_token_type::number;
        token.str = number_str;
        advance(number_str.size() - 1);
    } else {
        // If it's not a number, it must be an operator
        token.str = substr(token.index, 1);
        token.type = sql_token_type::binary_operator;
    }

    tokens_.emplace_back(token);
}

void pgsql_tokenizer::tokenize_operator_or_number()
{
    sql_token token;
    token.index = index();

    auto number_str = extract_number(substr(index()));
    if (!number_str.empty()) {
        token.type = sql_token_type::number;
        token.str = number_str;
        advance(number_str.size() - 1);
    } else {
        // If it's not a number, it must be an operator
        token.str = substr(token.index, 1);
        token.type = sql_token_type::binary_operator;
    }

    tokens_.emplace_back(token);
}

void pgsql_tokenizer::tokenize_dollar_string_or_identifier()
{
    // This can be ambiguous as a dollar quoted string could match this pattern
    auto str = substr();

    re2::StringPiece parameter;
    const re2::StringPiece ref(str.data(), str.size());
    if (re2::RE2::PartialMatch(ref, *parameter_regex, &parameter)) {
        if (!parameter.empty()) {
            add_token(sql_token_type::identifier, ref.size());
        }
    } else {
        tokenize_string('$', sql_token_type::dollar_quoted_string);
    }
}

std::vector<sql_token> pgsql_tokenizer::tokenize_impl()
{
    for (; !eof(); advance()) {
        auto c = peek();
        // TODO use an array of characters or a giant switch?
        if (ddwaf::isalpha(c) || c == '_' ||
            static_cast<unsigned char>(c) > 0x7f) { // Command or identifier
            tokenize_command_operator_or_identifier();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number();
        } else if (c == '"') { // Double-quoted string
            tokenize_string('"', sql_token_type::double_quoted_string);
        } else if (c == '\'') { // Single-quoted string
            tokenize_string('\'', sql_token_type::single_quoted_string);
        } else if (c == '`') { // Backtick-quoted string
            tokenize_string('`', sql_token_type::back_quoted_string);
        } else if (c == '$') { // Dollar-quoted string or identifier
            tokenize_dollar_string_or_identifier();
        } else if (c == '(') {
            add_token(sql_token_type::parenthesis_open);
        } else if (c == ')') {
            add_token(sql_token_type::parenthesis_close);
        } else if (c == '.') {
            add_token(sql_token_type::dot);
        } else if (c == ',') {
            add_token(sql_token_type::comma);
        } else if (c == '?') {
            // JSON Operators ?| ?& ?
            auto n = next();
            if (n == '|' || n == '&') {
                add_token(sql_token_type::binary_operator, 2);
            } else {
                add_token(sql_token_type::binary_operator);
            }
        } else if (c == '#') {
            // JSON Operators #>> #> #-
            auto n = next();
            if (n == '>') {
                add_token(sql_token_type::binary_operator, next(2) == '>' ? 3 : 2);
            } else if (n == '-') {
                add_token(sql_token_type::binary_operator, 2);
            }
        } else if (c == '*') {
            add_token(sql_token_type::asterisk);
        } else if (c == ';') {
            add_token(sql_token_type::query_end);
        } else if (c == '/') {
            tokenize_inline_comment_or_operator();
        } else if (c == '-') {
            tokenize_eol_comment_operator_or_number();
        } else if (c == '+') {
            tokenize_operator_or_number();
        } else if (c == '@') {
            auto n = next();
            if (n == '@' || n == '>') {
                add_token(sql_token_type::binary_operator, 2);
            }
        } else if (c == '!') {
            add_token(sql_token_type::binary_operator, next() == '=' ? 2 : 1);
        } else if (c == '>') {
            auto n = next();
            if (n == '>' || n == '=') {
                add_token(sql_token_type::binary_operator, 2);
            } else {
                add_token(sql_token_type::binary_operator);
            }
        } else if (c == '<') {
            auto n = next();
            if (n == '=' || n == '@') {
                add_token(sql_token_type::binary_operator, next(2) == '>' ? 3 : 2);
            } else if (n == '<' || n == '>') {
                add_token(sql_token_type::binary_operator, 2);
            } else {
                add_token(sql_token_type::binary_operator);
            }
        } else if (c == '=' || c == '%') {
            add_token(sql_token_type::binary_operator);
        } else if (c == '|') {
            if (next() == '|') {
                add_token(sql_token_type::binary_operator, 2);
            } else {
                add_token(sql_token_type::bitwise_operator);
            }
        } else if (c == '&' || c == '^' || c == '~') {
            add_token(sql_token_type::bitwise_operator);
        } else if (c == ':') {
            auto n = next();
            if (n == '=') {
                add_token(sql_token_type::binary_operator);
            } else if (n == ':') {
                add_token(sql_token_type::command);
            } else {
                add_token(sql_token_type::label);
            }
        } else if (c == '[') {
            add_token(sql_token_type::array_open);
        } else if (c == ']') {
            add_token(sql_token_type::array_close);
        }
    }
    return tokens_;
}

} // namespace ddwaf
