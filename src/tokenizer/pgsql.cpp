// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "tokenizer/pgsql.hpp"
#include "regex_utils.hpp"
#include "utils.hpp"

namespace ddwaf {
namespace {

/*
 * https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS
 * SQL identifiers and key words must begin with a letter (a-z, but also letters with diacritical
 * marks and non-Latin letters) or an underscore (_). Subsequent characters in an identifier or key
 * word can be letters, underscores, digits (0-9), or dollar signs ($). Note that dollar signs are
 * not allowed in identifiers according to the letter of the SQL standard, so their use might render
 * applications less portable. The SQL standard will not define a key word that contains digits or
 * starts or ends with an underscore, so identifiers of this form are safe against possible conflict
 * with future extensions of the standard.
 */
constexpr std::string_view identifier_regex_str =
    R"((?i)^(?:(?P<command>SELECT|FROM|WHERE|GROUP\s+BY|OFFSET|LIMIT|HAVING|ORDER\s+BY|PARTITION\s+BY|ASC|DESC)|^(?P<binary_operator>OR|XOR|AND|IN|BETWEEN|LIKE|REGEXP|SOUNDS\s+LIKE|IS\s+NULL|IS\s+NOT\s+NULL|NOT|IS|MOD|DIV)|^(?P<identifier>[\x{0080}-\x{FFFF}a-zA-Z_][\x{0080}-\x{FFFF}a-zA-Z_0-9$]*))(?:\b|\s|$))";

constexpr std::string_view parameter_regex_str = R"(^(\$[0-9]+)(?:\b|\s|$))";

auto identifier_regex = regex_init_nothrow(identifier_regex_str);
auto parameter_regex = regex_init_nothrow(parameter_regex_str);

} // namespace

pgsql_tokenizer::pgsql_tokenizer(
    std::string_view str, std::unordered_set<sql_token_type> skip_tokens)
    : sql_tokenizer(str, std::move(skip_tokens))
{
    if (!identifier_regex) {
        throw std::runtime_error("pgsql identifier regex not valid");
    }

    if (!parameter_regex) {
        throw std::runtime_error("pgsql parameter regex not valid");
    }
}

void pgsql_tokenizer::tokenize_command_operator_or_identifier()
{
    sql_token token;
    token.index = index();

    auto remaining_str = substr(index());

    re2::StringPiece binary_op;
    re2::StringPiece command;
    re2::StringPiece ident;

    // TODO recognize escape and bit string constants
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
    emplace_token(token);
}

void pgsql_tokenizer::tokenize_eol_comment()
{
    // Inline comment
    sql_token token;
    token.index = index();

    while (advance() && peek() != '\n') {}

    token.str = substr(token.index, index() - token.index);
    token.type = sql_token_type::eol_comment;
    emplace_token(token);
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

void pgsql_tokenizer::tokenize_operator_or_number()
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

void pgsql_tokenizer::tokenize_dollar_quoted_string()
{
    // https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-DOLLAR-QUOTING
    sql_token token;
    token.index = index();
    token.type = sql_token_type::dollar_quoted_string;

    while (advance()) {
        auto c = peek();
        if (!ddwaf::isalnum(c) && c != '_' && static_cast<uint8_t>(c) <= 0x7f) {
            break;
        }
    }

    if (peek() != '$') {
        // Unclear what we've found, ignore it and move on
        return;
    }

    // We found a valid tag, we should find the end tag
    auto tag = substr(token.index, index() - token.index + 1);
    while (advance()) {
        // Dollar quoted strings can be nested so we must check the tag
        if (peek() == '$' && substr().starts_with(tag)) {
            advance(tag.size() - 1);
            break;
        }
    }

    // At this point we either added a token or we found an unterminated dollar
    // quoted string constant...
    token.str = substr(token.index, index() - token.index + 1);
    emplace_token(token);
}

void pgsql_tokenizer::tokenize_dollar_string_or_identifier()
{
    // Dollar quoted string tags can't start with numeric characters, while
    // variables can only contain numeric characters.
    auto n = next();
    if (ddwaf::isalpha(n) || n == '_' || n == '$' || static_cast<uint8_t>(n) > 0x7f) {
        tokenize_dollar_quoted_string();
    } else {
        auto str = substr();

        re2::StringPiece parameter;
        const re2::StringPiece ref(str.data(), str.size());
        if (re2::RE2::PartialMatch(ref, *parameter_regex, &parameter)) {
            if (!parameter.empty()) {
                add_token(sql_token_type::identifier, ref.size());
            }
        }
    }
}

std::vector<sql_token> pgsql_tokenizer::tokenize_impl()
{
    for (; !eof(); advance()) {
        auto c = peek();
        // TODO use an array of characters or a giant switch?
        if (ddwaf::isalpha(c) || c == '_' || static_cast<uint8_t>(c) > 0x7f) {
            // Command or identifier
            tokenize_command_operator_or_identifier();
        } else if (ddwaf::isdigit(c)) {
            tokenize_number();
        } else if (c == '"') {
            // Double quoted strings in pgsql are considered identifiers:
            // https://www.postgresql.org/docs/current/sql-syntax-lexical.html#SQL-SYNTAX-IDENTIFIERS
            tokenize_string('"', sql_token_type::identifier);
        } else if (c == '\'') {
            // Single-quoted string constants
            tokenize_string('\'', sql_token_type::single_quoted_string);
        } else if (c == '`') {
            // Backtick-quoted string, in theory this aren't supported although
            // supporting them doesn't hurt
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
            if (n == '=') {
                add_token(sql_token_type::binary_operator, next(2) == '>' ? 3 : 2);
            } else if (n == '@' || n == '<' || n == '>') {
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
                add_token(sql_token_type::binary_operator, 2);
            } else if (n == ':') {
                add_token(sql_token_type::command, 2);
            } else {
                add_token(sql_token_type::colon);
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
