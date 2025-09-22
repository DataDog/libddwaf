// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <memory>
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

#include "log.hpp"
#include "re2.h"
#include "tokenizer/sql_base.hpp"
#include "tokenizer/sqlite.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {
namespace {
// https://www.sqlite.org/lang_select.html
// Identifiers: https://sqlite.org/lang_keywords.html
constexpr std::string_view identifier_regex_initialiser =
    R"((?i)^(?:(?P<keyword>SELECT|DISTINCT|ALL|FROM|WHERE|GROUP|HAVING|WINDOW|VALUES|OFFSET|LIMIT|ORDER|BY|ASC|DESC|UNION|INTERSECT|EXCEPT|NULL|AS)|(?P<binary_operator>OR|AND|IN|BETWEEN|LIKE|GLOB|ESCAPE|COLLATE|REGEXP|MATCH|NOTNULL|ISNULL|NOT|IS)|(?P<identifier>[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*|\$[0-9]+))(?:\b|\s|$))";

std::unique_ptr<re2::RE2> identifier_regex;

} // namespace

bool sqlite_tokenizer::initialise_regexes()
{
    static const bool ret = []() {
        try {
            const bool parent_init = sql_tokenizer<sqlite_tokenizer>::initialise_regexes();
            identifier_regex = std::make_unique<re2::RE2>(identifier_regex_initialiser);
            return parent_init && identifier_regex->ok();
        } catch (...) {
            return false;
        }
    }();

    return ret;
}

sqlite_tokenizer::sqlite_tokenizer(
    std::string_view str, std::unordered_set<sql_token_type> skip_tokens)
    : sql_tokenizer(str, std::move(skip_tokens))
{
    if (!initialise_regexes()) {
        throw std::runtime_error(
            "sqlite identifier regex not valid: " + identifier_regex->error_arg());
    }
}

void sqlite_tokenizer::tokenize_keyword_operator_or_identifier()
{
    sql_token token;
    token.index = index();

    auto remaining_str = substr(index());

    std::string_view binary_op;
    std::string_view keyword;
    std::string_view ident;

    const std::string_view ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, *identifier_regex, &keyword, &binary_op, &ident)) {
        // At least one of the strings will contain a match
        if (!binary_op.empty()) {
            token.type = sql_token_type::binary_operator;
            token.str = substr(token.index, binary_op.size());
            advance(token.str.size() - 1);
        } else if (!keyword.empty()) {
            token.type = sql_token_type::keyword;
            token.str = substr(token.index, keyword.size());
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

void sqlite_tokenizer::tokenize_eol_comment_or_operator_or_number()
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

    if (tokens_.empty() || current_token_type() != sql_token_type::number) {
        auto number_str = extract_number();
        if (!number_str.empty()) {
            sql_token token;
            token.index = index();
            token.type = sql_token_type::number;
            token.str = number_str;
            advance(number_str.size() - 1);
            emplace_token(token);
            return;
        }
    }

    // If it's not a number, it must be an operator
    add_token(sql_token_type::binary_operator);
}

std::vector<sql_token> sqlite_tokenizer::tokenize_impl()
{
    for (; !eof(); advance()) {
        auto c = peek();
        // TODO use an array of characters or a giant switch?
        if (ddwaf::isalpha(c) || c == '$' || c == '_' ||
            static_cast<unsigned char>(c) > 0x7f) { // Command or identifier
            tokenize_keyword_operator_or_identifier();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number();
        } else if (c == '"') {
            // Double-quoted string, considered an identifier
            tokenize_conforming_string('"', sql_token_type::identifier);
        } else if (c == '\'') {
            // Single-quoted string
            tokenize_conforming_string('\'', sql_token_type::single_quoted_string);
        } else if (c == '`') {
            // Backtick-quoted string, considered an identifier
            tokenize_conforming_string('`', sql_token_type::identifier);
        } else if (c == '[') {
            // If the end square bracket isn't found, all of the remaining
            // string will be considered part of the identifier
            add_token(sql_token_type::identifier, substr().find(']'));
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
            tokenize_eol_comment_or_operator_or_number();
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
        } else if (!ddwaf::isspace(c)) {
            DDWAF_DEBUG("Failed to parse sql statement {}, unexpected character {}", buffer_, c);
            return {};
        }
    }
    return tokens_;
}

} // namespace ddwaf
