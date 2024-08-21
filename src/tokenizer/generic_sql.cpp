// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "tokenizer/generic_sql.hpp"
#include "log.hpp"
#include "re2.h"
#include "stringpiece.h"
#include "tokenizer/sql_base.hpp"
#include "utils.hpp"
#include <stdexcept>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

using namespace std::literals;

namespace ddwaf {
namespace {
re2::RE2 identifier_regex(
    R"((?i)^(?:(?P<keyword>SELECT|FROM|WHERE|GROUP|OFFSET|LIMIT|DISTINCT|HAVING|ORDER|ASC|DESC|UNION|NULL|ALL|ANY|BY|AS)|(?P<binary_operator>OR|AND|BETWEEN|LIKE|IN|MOD|IS|NOT)|(?P<identifier>[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*))(?:\b|\s|$))");

} // namespace

generic_sql_tokenizer::generic_sql_tokenizer(
    std::string_view str, std::unordered_set<sql_token_type> skip_tokens)
    : sql_tokenizer(str, std::move(skip_tokens))
{
    if (!identifier_regex.ok()) {
        throw std::runtime_error("sql identifier regex not valid: " + identifier_regex.error_arg());
    }
}

void generic_sql_tokenizer::tokenize_keyword_operator_or_identifier()
{
    sql_token token;
    token.index = index();

    auto remaining_str = substr(index());

    re2::StringPiece binary_op;
    re2::StringPiece keyword;
    re2::StringPiece ident;

    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, identifier_regex, &keyword, &binary_op, &ident)) {
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

void generic_sql_tokenizer::tokenize_inline_comment_or_operator()
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

void generic_sql_tokenizer::tokenize_eol_comment()
{
    // Inline comment
    sql_token token;
    token.index = index();

    while (advance() && peek() != '\n') {}

    token.str = substr(token.index, index() - token.index);
    token.type = sql_token_type::eol_comment;
    emplace_token(token);
}

void generic_sql_tokenizer::tokenize_eol_comment_or_operator()
{
    if (next() == '-') {
        tokenize_eol_comment();
        return;
    }

    sql_token token;
    token.index = index();
    token.str = substr(token.index, 1);
    token.type = sql_token_type::binary_operator;
    emplace_token(token);
}

std::vector<sql_token> generic_sql_tokenizer::tokenize_impl()
{
    for (; !eof(); advance()) {
        auto c = peek();
        // TODO use an array of characters or a giant switch?
        if (ddwaf::isalpha(c) || c == '_' ||
            static_cast<unsigned char>(c) > 0x7f) { // Command or identifier
            tokenize_keyword_operator_or_identifier();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number();
        } else if (c == '"') {
            // For compatibility, double-quoted strings are always considered
            // identifiers.
            tokenize_escaped_string('"', sql_token_type::identifier);
        } else if (c == '\'') { // Single-quoted string
            tokenize_escaped_string('\'', sql_token_type::single_quoted_string);
        } else if (c == '`') { // Backtick-quoted string
            tokenize_escaped_string('`', sql_token_type::back_quoted_string);
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
            tokenize_eol_comment_or_operator();
        } else if (c == '#') {
            tokenize_eol_comment();
        } else if (c == '!' || c == '>') {
            add_token(sql_token_type::binary_operator, next() == '=' ? 2 : 1);
        } else if (c == '<') {
            auto n = next();
            if (n == '=' || n == '>') {
                add_token(sql_token_type::binary_operator, 2);
            } else {
                add_token(sql_token_type::binary_operator);
            }
        } else if (c == '=' || c == '%' || c == '+') {
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
            add_token(sql_token_type::colon);
        } else if (!ddwaf::isspace(c)) {
            DDWAF_DEBUG("Failed to parse sql statement {}, unexpected character {}", buffer_, c);
            return {};
        }
    }
    return tokens_;
}

} // namespace ddwaf
