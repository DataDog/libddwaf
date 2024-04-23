// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "tokenizer/sqlite.hpp"
#include "regex_utils.hpp"
#include "utils.hpp"

namespace ddwaf {
namespace {
// https://www.sqlite.org/lang_select.html
constexpr std::string_view identifier_regex_str =
    R"((?i)^(?:(?P<command>SELECT|DISTINCT|ALL|FROM|WHERE|GROUP BY|HAVING|WINDOW|AS|VALUES|OFFSET|LIMIT|ORDER BY|ASC|DESC|UNION ALL|UNION|INTERSECT|EXCEPT)|(?P<binary_operator>OR|AND|IN|BETWEEN|LIKE|GLOB|ESCAPE|COLLATE|REGEXP|IS DISTINCT FROM|IS NOT DISTINCT FROM|MATCH|NOTNULL|NOT NULL|ISNULL|IS NOT NULL|IS NOT|NOT|IS)|(?P<identifier>[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*|\$[0-9]+))(?:\b|\s|$))";

auto identifier_regex = regex_init_nothrow(identifier_regex_str);

} // namespace

sqlite_tokenizer::sqlite_tokenizer(
    std::string_view str, std::unordered_set<sql_token_type> skip_tokens)
    : sql_tokenizer(str, std::move(skip_tokens))
{
    if (!identifier_regex) {
        throw std::runtime_error("sqlite identifier regex not valid");
    }
}

void sqlite_tokenizer::tokenize_command_operator_or_identifier()
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
        emplace_token(token);
    }
}

void sqlite_tokenizer::tokenize_inline_comment_or_operator()
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
    emplace_token(token);
}

void sqlite_tokenizer::tokenize_eol_comment()
{
    // Inline comment
    sql_token token;
    token.index = index();

    while (advance() && peek() != '\n') {}

    token.str = substr(token.index, index() - token.index);
    token.type = sql_token_type::eol_comment;
    emplace_token(token);
}

void sqlite_tokenizer::tokenize_eol_comment_operator_or_number()
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

    auto number_str = extract_number();
    if (!number_str.empty()) {
        token.type = sql_token_type::number;
        token.str = number_str;
        advance(number_str.size() - 1);
    } else {
        // If it's not a number, it must be an operator
        token.str = substr(token.index, 1);
        token.type = sql_token_type::binary_operator;
    }

    emplace_token(token);
}

void sqlite_tokenizer::tokenize_operator_or_number()
{
    sql_token token;
    token.index = index();

    auto number_str = extract_number();
    if (!number_str.empty()) {
        token.type = sql_token_type::number;
        token.str = number_str;
        advance(number_str.size() - 1);
    } else {
        // If it's not a number, it must be an operator
        token.str = substr(token.index, 1);
        token.type = sql_token_type::binary_operator;
    }

    emplace_token(token);
}

std::vector<sql_token> sqlite_tokenizer::tokenize_impl()
{
    for (; !eof(); advance()) {
        auto c = peek();
        // TODO use an array of characters or a giant switch?
        if (ddwaf::isalpha(c) || c == '$' || c == '_' ||
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
        } else if (c == '-') {
            tokenize_eol_comment_operator_or_number();
        } else if (c == '+') {
            tokenize_operator_or_number();
        } else if (c == '!' && next() == '=') {
            add_token(sql_token_type::binary_operator, 2);
        } else if (c == '>') {
            auto n = next();
            if (n == '>' || n == '=') {
                add_token(sql_token_type::binary_operator, 2);
            } else {
                add_token(sql_token_type::binary_operator);
            }
        } else if (c == '<') {
            auto n = next();
            if (n == '=') {
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
        } else if (c == '&' || c == '~') {
            add_token(sql_token_type::bitwise_operator);
        } else if (c == ':') {
            add_token(sql_token_type::colon);
        }
    }
    return tokens_;
}

} // namespace ddwaf
