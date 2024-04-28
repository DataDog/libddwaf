// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "tokenizer/mysql.hpp"
#include "utils.hpp"

namespace ddwaf {
namespace {

// Operators: https://dev.mysql.com/doc/refman/5.7/en/built-in-function-reference.html
// Identifiers: https://dev.mysql.com/doc/refman/8.0/en/identifiers.html
re2::RE2 identifier_regex(
    R"((?i)^(?:(?P<command>SELECT|ALL|DISTINCT|DISTINCTROW|HIGH_PRIORITY|STRAIGHT_JOIN|SQL_SMALL_RESULT|SQL_BIG_RESULT|SQL_BUFFER_RESULT|SQL_NO_CACHE|SQL_CALC_FOUND_ROWS|FROM|PARTITION|WHERE|GROUP|WITH|ROLLUP|UNION|INTERSECT|EXCEPT|HAVING|WINDOW|ORDER|CASE|NULL|BY|ASC|DESC|LIMIT|OFFSET|ALL|AS)|(?P<binary_operator>MOD|AND|BETWEEN|BINARY|DIV|LAST_DAY|REGEXP|XOR|OR|RLIKE|SOUNDS|LIKE|NOT|IN|IS)|(?P<identifier>[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*))(?:\b|\s|$))");

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
re2::RE2 variable_regex(
    R"(^(@@?(:?`([^\\`]|\\.)*`|'([^\\']|\\.)*'|"([^\\"]|\\.)*"|[a-zA-Z0-9$_]+)(:?\.(:?`([^\\`]|\\.)*`|'([^\\']|\\.)*'|"([^\\"]|\\.)*"|[a-zA-Z0-9$_]*))*))");

// Number of identifier starting by a number, note that these identifiers must always have other
// characters and can't consist only of numbers.
// https://dev.mysql.com/doc/refman/5.7/en/identifiers.html
re2::RE2 number_or_identifier_regex(
    R"((?i)^(?:(?P<number>0x[0-9a-fA-F]+|[-+]*(?:[0-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\b)|(?P<identifier>[0-9][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*))(?:\b|\s|$))");

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

std::string_view extract_variable(std::string_view str)
{
    return partial_match_regex(variable_regex, str);
}

} // namespace

mysql_tokenizer::mysql_tokenizer(
    std::string_view str, std::unordered_set<sql_token_type> skip_tokens)
    : sql_tokenizer(str, std::move(skip_tokens))
{
    if (!identifier_regex.ok()) {
        throw std::runtime_error(
            "mysql identifier regex not valid: " + identifier_regex.error_arg());
    }

    if (!variable_regex.ok()) {
        throw std::runtime_error("mysql variable regex not valid: " + variable_regex.error_arg());
    }

    if (!number_or_identifier_regex.ok()) {
        throw std::runtime_error("mysql number of identifier regex not valid: " +
                                 number_or_identifier_regex.error_arg());
    }
}

void mysql_tokenizer::tokenize_command_operator_or_identifier()
{
    sql_token token;
    token.index = index();

    auto remaining_str = substr(index());

    re2::StringPiece binary_op;
    re2::StringPiece command;
    re2::StringPiece ident;

    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, identifier_regex, &command, &binary_op, &ident)) {
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

void mysql_tokenizer::tokenize_inline_comment_or_operator()
{
    // The first character is / so it can be a comment or a binary operator
    sql_token token;
    token.index = index();
    if (advance() && peek() == '*') {
        advance(); // Skip the '*' in prev()
        if (peek() == '!') {
            // https://dev.mysql.com/doc/refman/8.0/en/comments.html
            // These types of comments contain actual SQL code and are primarily
            // used for MySQL-specific extensions. We can ignore the comment
            // start token and end token.
            return;
        }

        // Comment
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

void mysql_tokenizer::tokenize_number_or_identifier()
{
    sql_token token;
    token.index = index();

    auto remaining_str = substr(index());

    re2::StringPiece number;
    re2::StringPiece ident;

    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, number_or_identifier_regex, &number, &ident)) {
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
        emplace_token(token);
    }
}

void mysql_tokenizer::tokenize_variable()
{
    sql_token token;
    token.index = index();
    token.type = sql_token_type::identifier;
    token.str = extract_variable(substr());
    if (!token.str.empty()) {
        emplace_token(token);
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
    emplace_token(token);
}

void mysql_tokenizer::tokenize_eol_comment_operator_or_number()
{
    auto n = next();
    auto n2 = next(2);
    if (n == '-' && (ddwaf::isspace(n2) || n2 == '\0')) {
        // https://dev.mysql.com/doc/refman/8.0/en/ansi-diff-comments.html
        // EOL Comments in MySQL require a whitespace after --
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

void mysql_tokenizer::tokenize_operator_or_number()
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

std::vector<sql_token> mysql_tokenizer::tokenize_impl()
{
    for (; !eof(); advance()) {
        auto c = peek();
        // TODO use an array of characters or a giant switch?
        if (ddwaf::isalpha(c) || c == '_' || static_cast<uint8_t>(c) > 0x7f) {
            // Command or identifier
            tokenize_command_operator_or_identifier();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number_or_identifier();
        } else if (c == '"') {
            // Double-quoted string, this can also be considered an identifier
            // if the ANSI_QUOTE mode is enabled, however we have no way of
            // knowing
            tokenize_string('"', sql_token_type::double_quoted_string);
        } else if (c == '\'') { // Single-quoted string
            tokenize_string('\'', sql_token_type::single_quoted_string);
        } else if (c == '`') {
            // Backtick-quoted strings are considered identifiers
            tokenize_string('`', sql_token_type::identifier);
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
            // Since we're intentionally not tokenizing comments containing
            // MySQL extensions (i.e. /*! ... */), we must skip the end token.
            if (next() != '/') {
                add_token(sql_token_type::asterisk);
            } else {
                // Skip the whole inline comment end token "*/"
                advance();
            }
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
                add_token(sql_token_type::colon);
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
