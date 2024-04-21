// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "tokenizer/mysql.hpp"
#include "regex_utils.hpp"
#include "utils.hpp"

#include <iostream>

namespace ddwaf {
namespace {

// Operators: https://dev.mysql.com/doc/refman/5.7/en/built-in-function-reference.html
constexpr std::string_view identifier_regex_str =
    R"((?i)(?P<command>SELECT|ALL|DISTINCT|DISTINCTROW|HIGH_PRIORITY|STRAIGHT_JOIN|SQL_SMALL_RESULT|SQL_BIG_RESULT|SQL_BUFFER_RESULT|SQL_NO_CACHE|SQL_CALC_FOUND_ROWS|FROM|PARTITION|WHERE|GROUP BY|WITH ROLLUP|UNION ALL|UNION|INTERSECT|EXCEPT|HAVING|WINDOW|ORDER BY|ASC|DESC|LIMIT|OFFSET|AS)\b|(?P<binary_operator>MOD|AND|BETWEEN|BINARY|CASE|DIV|IS NULL|IS NOT NULL|IS NOT|IS|LAST_DAY|NOT BETWEEN|NOT LIKE|NOT REGEXP|NOT|REGEXP|XOR|OR|RLIKE|SOUNDS LIKE|LIKE)\b|(?P<identifier>[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*\b))";

/*
 *  https://dev.mysql.com/doc/refman/8.0/en/user-variables.html

 *  Variables are tricky to parse. We are going to explain how we got to the regex just below in
 *  this comment. First, all variables must start with @ for user variables, or @@ for system
 *  variables The default charset then is [a-zA-Z0-9$_]. This result in the regex @[a-zA-Z0-9$_]*
 *          (yes, empty name are tolerated)
 *
 *  You can however use a larger charset by using quotes, with something like '[^']*'
 *  Three different styles of quotes (', " and `) are allowed, resulting in the pattern being
 *  duplicated a few times into '[^']*'|`[^`]*`|"[^"]*"
 *  Escaping is allowed, meaning that @'var\' is not valid. This require updating the regex above
 *  with a check for escaping, '[^\\']|\\.'
 *      (\ have to be escaped, so every \\ is actually only one backslash)
 *      This result in allowing every character but backslash, or a backslash and the escaped
 *      character following.
 *
 *  We can then combine all that in the following (a) pattern
 *      @(`([^\\`]|\\.)*`|'([^\\']|\\.)*'|"([^\\"]|\\.)*"|[a-zA-Z0-9$_]*)
 *  This pattern describes the sequence of characters using the default charset, and the sequence
 *  escaped for each quote style. The default sequence must be placed at the end, or it may greedly
 *  "match" 0 characters in the  presence of quotes
 *
 *  Unfortunately, you can do more with a MySQL variable: you also can access subitems, using
 *  @var.sub. All the syntax quirks for the main name apply for the subitem, so we need to
 *  duplicate the pattern, and replace the starting character by .
 *      \.(`([^\\`]|\\.)*`|'([^\\']|\\.)*'|"([^\\"]|\\.)*"|[a-zA-Z0-9$_]*)
 *
 *  Because subitems are optional, and not limited in depth, we use the * operator to any
 *  occurence (b)
 *      (\.(`([^\\`]|\\.)*`|'([^\\']|\\.)*'|"([^\\"]|\\.)*"|[a-zA-Z0-9$_]*))*
 *
 *  By taking the (a) patterns and putting (b) just after, you end up with the regexp we use to
 *  parse the variable.
 */
constexpr std::string_view variable_regex_str =
    R"((@@?(:?`([^\\`]|\\.)*`|'([^\\']|\\.)*'|"([^\\"]|\\.)*"|[a-zA-Z0-9$_]+)(:?\.(:?`([^\\`]|\\.)*`|'([^\\']|\\.)*'|"([^\\"]|\\.)*"|[a-zA-Z0-9$_]*))*))";

// Hexadecimal, octal, decimal or floating point
constexpr std::string_view number_regex_str =
    R"((?i)(0x[0-9a-fA-F]+|[-+]*(?:[0-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b))";

// Number of identifier starting by a number, note that these identifiers must always have other
// characters and can't consist only of numbers.
// https://dev.mysql.com/doc/refman/5.7/en/identifiers.html
constexpr std::string_view number_or_identifier_regex_str =
    R"((?i)(?P<number>0x[0-9a-fA-F]+|[-+]*(?:[0-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b)|(?P<identifier>[0-9][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*\b))";

auto identifier_regex = regex_init(identifier_regex_str);
auto variable_regex = regex_init(variable_regex_str);
auto number_regex = regex_init(number_regex_str);
auto number_or_identifier_regex = regex_init(number_or_identifier_regex_str);

std::string_view partial_match_regex(re2::RE2 &regex, std::string_view str)
{
    re2::StringPiece match;
    const re2::StringPiece ref(str.data(), str.size());
    if (re2::RE2::PartialMatch(ref, regex, &match)) {
        if (!match.empty()) {
            return {match.data(), match.size()};
        }
    }
    return {};
}

std::string_view extract_number(std::string_view str)
{
    return partial_match_regex(*number_regex, str);
}

std::string_view extract_variable(std::string_view str)
{
    return partial_match_regex(*variable_regex, str);
}

} // namespace

void mysql_tokenizer::tokenize_command_operator_or_identifier()
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

void mysql_tokenizer::tokenize_inline_comment_or_operator()
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

void mysql_tokenizer::tokenize_number_or_identifier()
{
    sql_token token;
    token.index = index();

    auto remaining_str = substr(index());

    re2::StringPiece number;
    re2::StringPiece ident;

    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, *number_or_identifier_regex, &number, &ident)) {
        // At least one of the strings will contain a match
        if (!number.empty()) {
            token.type = sql_token_type::number;
            token.str = substr(token.index, number.size());
            advance(token.str.size() - 1);
        } else if (!ident.empty()) {
            token.type = sql_token_type::identifier;
            token.str = substr(token.index, ident.size());
            advance(token.str.size() - 1);
        }
        tokens_.emplace_back(token);
    }
}

void mysql_tokenizer::tokenize_variable()
{
    sql_token token;
    token.index = index();
    token.type = sql_token_type::identifier;
    token.str = extract_variable(substr());
    if (!token.str.empty()) {
        tokens_.emplace_back(token);
        advance(token.str.size() - 1);
    }
}

void mysql_tokenizer::tokenize_eol_comment()
{
    // Inline comment
    sql_token token;
    token.index = index();

    while (advance() && peek() != '\n') {}

    token.str = substr(token.index, index() - token.index);
    token.type = sql_token_type::eol_comment;
    tokens_.emplace_back(token);
}

void mysql_tokenizer::tokenize_eol_comment_operator_or_number()
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

void mysql_tokenizer::tokenize_operator_or_number()
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

std::vector<sql_token> mysql_tokenizer::tokenize_impl()
{
    for (; !eof(); advance()) {
        auto c = peek();
        // TODO use an array of characters or a giant switch?
        if (ddwaf::isalpha(c) || c == '_' ||
            static_cast<unsigned char>(c) > 0x7f) { // Command or identifier
            tokenize_command_operator_or_identifier();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number_or_identifier();
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
        } else if (c == '#') {
            tokenize_eol_comment();
        } else if (c == '+') {
            tokenize_operator_or_number();
        } else if (c == '@') {
            tokenize_variable();
        } else if (c == '!') {
            add_token(sql_token_type::binary_operator, next() == '=' ? 2 : 1);
        } else if (c == '>') {
            auto n = next();
            if (n == '>') {
                add_token(sql_token_type::bitwise_operator, 2);
            } else if (n == '=') {
                add_token(sql_token_type::binary_operator, 2);
            } else {
                add_token(sql_token_type::binary_operator);
            }
        } else if (c == '<') {
            auto n = next();
            if (n == '=') {
                add_token(sql_token_type::binary_operator, next(2) == '>' ? 3 : 2);
            } else if (n == '<') {
                add_token(sql_token_type::bitwise_operator, 2);
            } else if (n == '>') {
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
            if (next() == '&') {
                add_token(sql_token_type::binary_operator, 2);
            } else {
                add_token(sql_token_type::bitwise_operator);
            }
        } else if (c == ':') {
            if (next() == '=') {
                add_token(sql_token_type::binary_operator, 2);
            } else {
                add_token(sql_token_type::label);
            }
        } else if (c == '{') {
            add_token(sql_token_type::curly_brace_open);
        } else if (c == '}') {
            add_token(sql_token_type::curly_brace_close);
        }
    }
    return tokens_;
}

} // namespace ddwaf
