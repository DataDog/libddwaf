// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "sql_tokenizer.hpp"
#include "utils.hpp"

namespace ddwaf {
namespace {
constexpr std::string_view identifier_regex_str = R"((?i)(?P<command>SELECT|FROM|WHERE|ORDER BY)|(?P<binary_operator>NOT|OR|XOR|AND|IS|IN|BETWEEN|LIKE|REGEXP|SOUNDS LIKE|IS NULL|IS NOT NULL)|(?P<bitwise_operator>DIV|MOD)|(?P<identifier>[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$\.]*))";
constexpr std::string_view number_regex_str = R"((?i)(0x[0-9a-fA-F]+|[-+]*(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?))";

thread_local re2::RE2 identifier_regex(identifier_regex_str);
thread_local re2::RE2 number_regex(number_regex_str);

}

sql_tokenizer::sql_tokenizer(std::string_view str): buffer_(str) {
    if (!identifier_regex.ok()) {
        throw std::runtime_error("failed");
    }

    if (!number_regex.ok()) {
        throw std::runtime_error("failed");
    }
}


void sql_tokenizer::tokenize_command_operator_or_identifier()
{
    sql_token token;
    token.index = index();

    auto remaining_str = substr(index());

    re2::StringPiece binary_op, bitwise_op, command, ident;
    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, identifier_regex, &command, &bitwise_op, &binary_op, &ident)) {
        if (!binary_op.empty()) {
            token.type = sql_token_type::binary_operator;
            token.str = substr(token.index, binary_op.size());
            advance(token.str.size());
        } else if (!bitwise_op.empty()) {
            token.type = sql_token_type::bitwise_operator;
            token.str = substr(token.index, bitwise_op.size());
            advance(token.str.size());
        } else if (!command.empty()) {
            token.type = sql_token_type::command;
            token.str = substr(token.index, command.size());
            advance(token.str.size());
        } else if (!ident.empty()) {
            token.type = sql_token_type::identifier;
            token.str = substr(token.index, ident.size());
            advance(token.str.size());
        }
        tokens_.emplace_back(token);
        return;
    }

    advance();
}

void sql_tokenizer::tokenize_string(char quote)
{
    sql_token token;
    token.index = index();
    token.type = sql_token_type::double_quoted_string;
    while (advance()) {
        if (peek() == quote && prev() != '\\') {
            break;
        }
    }
    token.str = substr(token.index, index() - token.index + 1);
    tokens_.emplace_back(token);

    advance();
}

void sql_tokenizer::tokenize_inline_comment_or_operator()
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
        advance();
    } else {
        token.str = substr(token.index, 1);
        token.type = sql_token_type::binary_operator;
    }
    tokens_.emplace_back(token);
}

bool sql_tokenizer::tokenize_number()
{
    sql_token token;
    token.index = index();

    auto remaining_str = substr(index());

    re2::StringPiece number;
    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, number_regex, &number)) {
        if (!number.empty()) {
            token.str = substr(token.index, number.size());
            token.type = sql_token_type::number;
            advance(token.str.size());
            tokens_.emplace_back(token);
            return true;
        }
    }
    advance();
    return false;
}

void sql_tokenizer::tokenize_eol_comment()
{
    // Inline comment
    sql_token token;
    token.index = index();

    while (advance() && peek() != '\n' ) {}

    token.str = substr(token.index, index() - token.index);
    token.type = sql_token_type::eol_comment;
    tokens_.emplace_back(token);
}

void sql_tokenizer::tokenize_eol_comment_operator_or_number()
{
    if (next() == '-') {
        tokenize_eol_comment();
    } else if (!tokenize_number()) {
        // If it's not a number, it must be an operator
        sql_token token;
        token.index = index();
        token.str = substr(token.index, 1);
        token.type = sql_token_type::binary_operator;
        tokens_.emplace_back(token);
    }
}

void sql_tokenizer::tokenize_operator_or_number()
{
    if (!tokenize_number()) {
        // If it's not a number, it must be an operator
        sql_token token;
        token.index = index();
        token.str = substr(token.index, 1);
        token.type = sql_token_type::binary_operator;
        tokens_.emplace_back(token);
    }
}

std::vector<sql_token> sql_tokenizer::tokenize()
{
    while (!eof()) {
        auto c = ddwaf::tolower(peek());
        if (ddwaf::isalpha(c) || c == '_') { // Command or identifier
            tokenize_command_operator_or_identifier();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number();
        } else if (c == '"') { // Double-quoted string
            tokenize_string('"');
        } else if (c == '\'') { // Single-quoted string
            tokenize_string('\'');
        } else if (c == '`') { // Backtick-quoted string
            tokenize_string('`');
        } else if (c == '(') {
            add_token(sql_token_type::parenthesis_open);
        } else if (c == ')') {
            add_token(sql_token_type::parenthesis_close);
        } else if (c == '.') {
            add_token(sql_token_type::dot);
        } else if (c == ',') {
            add_token(sql_token_type::comma);
        } else if (c == '?') {
            add_token(sql_token_type::questionmark);
        } else if (c == '*') {
            add_token(sql_token_type::asterisk);
        } else if (c == ';') {
            add_token(sql_token_type::query_end);
        } else if (c == '/') {
            tokenize_inline_comment_or_operator();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number();
        } else if (c == '-') {
            tokenize_eol_comment_operator_or_number();
        } else if (c == '#') {
            tokenize_eol_comment();
        } else if (c == '+') {
            tokenize_operator_or_number();
        } else if (c == '@') {
            auto n = next();
            if (n == '@' || n == '>') {
                add_token(sql_token_type::binary_operator, 2);
            }
        } else if (c == '!') {
            add_token(sql_token_type::binary_operator, next() == '=' ? 2 : 1);
        } else if (c == '<') {
            auto n = next();
            if (n == '=' || n == '@') {
                add_token(sql_token_type::binary_operator, next(2) == '>' ? 3 : 2);
            } else if (n == '<' || n == '>') {
                add_token(sql_token_type::bitwise_operator, 2);
            } else {
                add_token(sql_token_type::binary_operator);
            }
        } else if (c == '>') {
            add_token(sql_token_type::binary_operator, next() == '=' ? 2 : 1);
        } else if (c == '=' || c == '%') {
            add_token(sql_token_type::binary_operator);
        } else if (c == '|') {
            add_token(sql_token_type::binary_operator, next() == '|' ? 2 : 1);
        } else if (c == '&' || c == '^' || c == '~') {
            add_token(sql_token_type::bitwise_operator);
        } else if (c == ':') {
            if (next() == '=') {
                add_token(sql_token_type::binary_operator);
            } else {
                add_token(sql_token_type::label);
            }
        } else if (ddwaf::isspace(c)) {
            advance();
        } else {
            advance();
        }

    }
    return tokens_;
}

}
