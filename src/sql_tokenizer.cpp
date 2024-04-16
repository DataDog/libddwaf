// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "sql_tokenizer.hpp"
#include "utils.hpp"
#include <iostream>

namespace ddwaf {
namespace {
constexpr std::string_view identifier_regex_str = R"((?i)(?P<command>SELECT|FROM|WHERE|ORDER BY)|(?P<binary_operator>NOT|OR|XOR|AND|IS|IN|BETWEEN|LIKE|REGEXP|SOUNDS LIKE|IS NULL|IS NOT NULL)|(?P<bitwise_operator>DIV|MOD)|(?P<identifier>[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$\.]*))";
constexpr std::string_view number_regex_str = R"((?i)(0x[0-9a-fA-F]+|[-+]*(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?))";

std::unique_ptr<re2::RE2> initialise_regex(std::string_view regex_str) {
    re2::RE2::Options options;
    options.set_log_errors(false);

    auto regex = std::make_unique<re2::RE2>(regex_str, options);
    if (regex == nullptr || !regex->ok()) {
        throw std::runtime_error("invalid regular expression: " + regex->error_arg());
    }
    return regex;
}

thread_local auto identifier_regex = initialise_regex(identifier_regex_str);
thread_local auto number_regex = initialise_regex(number_regex_str);


std::string_view extract_number(std::string_view str) {
    re2::StringPiece number;
    const re2::StringPiece ref(str.data(), str.size());
    if (re2::RE2::PartialMatch(ref, *number_regex, &number)) {
        if (!number.empty()) {
            return {number.data(), number.size()};
        }
    }
    return {};
}

}

void sql_tokenizer::tokenize_command_operator_or_identifier()
{
    sql_token token;
    token.index = index();

    auto remaining_str = substr(index());

    re2::StringPiece binary_op, bitwise_op, command, ident;
    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, *identifier_regex, &command, &bitwise_op, &binary_op, &ident)) {
        // At least one of the strings will contain a match
        if (!binary_op.empty()) {
            token.type = sql_token_type::binary_operator;
            token.str = substr(token.index, binary_op.size());
            advance(token.str.size() - 1);
        } else if (!bitwise_op.empty()) {
            token.type = sql_token_type::bitwise_operator;
            token.str = substr(token.index, bitwise_op.size());
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

void sql_tokenizer::tokenize_string(char quote, sql_token_type type)
{
    sql_token token;
    token.index = index();
    token.type = type;
    while (advance()) {
        if (peek() == quote && prev() != '\\') {
            break;
        }
    }
    token.str = substr(token.index, index() - token.index + 1);
    tokens_.emplace_back(token);
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
    } else {
        token.str = substr(token.index, 1);
        token.type = sql_token_type::binary_operator;
    }
    tokens_.emplace_back(token);
}

void sql_tokenizer::tokenize_number()
{
    sql_token token;
    token.index = index();
    token.type = sql_token_type::number;
    token.str = extract_number(substr(index()));
    if (!token.str.empty()) {
        tokens_.emplace_back(token);
    }
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

void sql_tokenizer::tokenize_operator_or_number()
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

std::vector<sql_token> sql_tokenizer::tokenize()
{
    for (; !eof(); advance()) {
        auto c = peek();
        if (ddwaf::isalpha(c) || c == '_') { // Command or identifier
            tokenize_command_operator_or_identifier();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number();
        } else if (c == '"') { // Double-quoted string
            tokenize_string('"', sql_token_type::double_quoted_string);
        } else if (c == '\'') { // Single-quoted string
            tokenize_string('\'', sql_token_type::single_quoted_string);
        } else if (c == '`') { // Backtick-quoted string
            tokenize_string('`', sql_token_type::back_quoted_string);
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
        } else if (c > 0x7F) {
            // TODO tokenize identifier only
            tokenize_command_operator_or_identifier();
        }
    }
    return tokens_;
}

sql_flavour sql_flavour_from_type(std::string_view type)
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


}
