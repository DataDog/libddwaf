// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "tokenizer/shell.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {
re2::RE2 redirection_regex(
    R"((&>>?|(?:[0-9]?>(?:\||>|&[0-9]?-?)?)|(?:[0-9]?<(?:<(?:-|<)?|&[0-9]?-?|>)?)))");

bool is_var_char(char c) { return ddwaf::isalnum(c) || c == '_'; }

bool is_field_char(char c)
{
    static constexpr std::string_view known_chars = "`${}[]()'\"#=|<>;&\n\t ";
    return known_chars.find(c) == std::string_view::npos;
}

} // namespace

std::ostream &operator<<(std::ostream &os, shell_tokenizer::shell_scope scope)
{
    using shell_scope = shell_tokenizer::shell_scope;

    switch (scope) {
    case shell_scope::global:
        os << "global";
        break;
    case shell_scope::double_quoted_string:
        os << "double_quoted_string";
        break;
    case shell_scope::backtick_substitution:
        os << "backtick_substitution";
        break;
    case shell_scope::command_substitution:
        os << "command_substitution";
        break;
    case shell_scope::compound_command:
        os << "command_grouping";
        break;
    case shell_scope::subshell:
        os << "subshell";
        break;
    case shell_scope::process_substitution:
        os << "process_substitution";
        break;
    }
    return os;
}

std::ostream &operator<<(std::ostream &os, shell_token_type type)
{
    switch (type) {
    case shell_token_type::unknown:
        os << "unknown";
        break;
    case shell_token_type::executable:
        os << "executable";
        break;
    case shell_token_type::field:
        os << "field";
        break;
    case shell_token_type::literal:
        os << "literal";
        break;
    case shell_token_type::double_quoted_string_open:
        os << "double_quoted_string_open";
        break;
    case shell_token_type::double_quoted_string_close:
        os << "double_quoted_string_close";
        break;
    case shell_token_type::double_quoted_string:
        os << "double_quoted_string";
        break;
    case shell_token_type::single_quoted_string:
        os << "single_quoted_string";
        break;
    case shell_token_type::control:
        os << "control";
        break;
    case shell_token_type::variable_definition:
        os << "variable_definition";
        break;
    case shell_token_type::variable:
        os << "variable";
        break;
    case shell_token_type::equal:
        os << "equal";
        break;
    case shell_token_type::backtick_substitution_open:
        os << "backtick_substitution_open";
        break;
    case shell_token_type::backtick_substitution_close:
        os << "backtick_substitution_close";
        break;
    case shell_token_type::dollar:
        os << "dollar";
        break;
    case shell_token_type::redirection:
        os << "redirection";
        break;
    case shell_token_type::command_substitution_open:
        os << "command_substitution_open";
        break;
    case shell_token_type::command_substitution_close:
        os << "command_substitution_close";
        break;
    case shell_token_type::parenthesis_open:
        os << "parenthesis_open";
        break;
    case shell_token_type::parenthesis_close:
        os << "parenthesis_close";
        break;
    case shell_token_type::curly_brace_open:
        os << "curly_brace_open";
        break;
    case shell_token_type::curly_brace_close:
        os << "curly_brace_close";
        break;
    case shell_token_type::process_substitution_open:
        os << "process_substitution_open";
        break;
    case shell_token_type::process_substitution_close:
        os << "process_substitution_close";
        break;
    case shell_token_type::subshell_open:
        os << "subshell_open";
        break;
    case shell_token_type::subshell_close:
        os << "subshell_close";
        break;
    case shell_token_type::compound_command_open:
        os << "compound_command_open";
        break;
    case shell_token_type::compound_command_close:
        os << "compound_command_close";
        break;
    }
    return os;
}

shell_tokenizer::shell_tokenizer(
    std::string_view str, std::unordered_set<shell_token_type> skip_tokens)
    : base_tokenizer(str, std::move(skip_tokens))
{
    scope_stack_.reserve(8);

    if (!redirection_regex.ok()) {
        throw std::runtime_error("redirection regex not valid: " + redirection_regex.error_arg());
    }
}

void shell_tokenizer::tokenize_delimited_token(std::string_view delimiter, shell_token_type type)
{
    shell_token token;
    token.index = index();
    token.type = type;

    std::size_t idx = 0;
    while (idx < delimiter.size() && advance()) {
        idx += static_cast<int>(peek() == delimiter[idx]);
    }

    token.str = substr(token.index, index() - token.index + 1);
    emplace_token(token);
}

void shell_tokenizer::tokenize_variable()
{
    shell_token token;
    token.index = index();
    if (should_expect_definition_or_executable()) {
        token.type = shell_token_type::executable;
    } else {
        token.type = shell_token_type::variable;
    }

    // Skip dollar
    advance();

    // We know the first character is $
    auto c = peek();
    if (c == '-' || c == '?' || c == '@' || c == '#' || c == '*' || c == '$' || c == '!' ||
        ddwaf::isdigit(c)) {
        // Special variable, these are one character long + dollar
        token.str = substr(token.index, 2);
    } else if (c == '{') {
        while (advance() && peek() != '}') {}
        token.str = substr(token.index, index() - token.index + 1);
    } else { // alphabetic
        while (is_var_char(next()) && advance()) {};
        token.str = substr(token.index, index() - token.index + 1);
    }

    emplace_token(token);
}

void shell_tokenizer::tokenize_double_quoted_string_scope()
{
    // Within a double quoted string, we need to search for either
    // arbitrary characters, an expansion or substitution and
    // the final quote, taking into consideration escaped quotes.
    auto begin = index();
    unsigned slash_count = 0;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-do-while)
    for (; !eof(); advance()) {
        auto c = peek();
        if (c == '"' && slash_count == 0) {
            pop_scope();

            // At this point we know there's at least one token so no need to check
            auto &token = last_token();
            if (token.type == shell_token_type::double_quoted_string_open) {
                if (should_expect_definition_or_executable()) {
                    token.type = shell_token_type::executable;
                } else {
                    token.type = shell_token_type::double_quoted_string;
                }
                token.str = substr(token.index, index() - token.index + 1);
            } else {
                if (begin < index()) {
                    shell_token token;
                    token.index = begin;
                    token.type = shell_token_type::literal;
                    token.str = substr(begin, index() - begin);
                    emplace_token(token);
                }

                add_token(shell_token_type::double_quoted_string_close);
            }
            break;
        }

        if (c == '$' && slash_count == 0) {
            auto n = next();
            if (n == '(' && next(2) != '(') {
                // Command substitution, we add a field for the current string
                // contents, update the scope and exit. Note that we skip
                // arithmetic expansions
                if (begin < index()) {
                    shell_token token;
                    token.index = begin;
                    token.type = shell_token_type::literal;
                    token.str = substr(begin, index() - begin);
                    emplace_token(token);
                }

                add_token(shell_token_type::command_substitution_open, 2);
                push_scope(shell_scope::command_substitution);
                break;
            }

            // Other interesting cases which we make part of the literal:
            // - Variables, which we ignore for now
            // - $[] legacy arithmetic expansion
            // - $(( ... )) arithmetic expansions
        } else if (c == '`') {
            // Backtick substitution, we add a literal for the current string
            // contents, update the scope and exit
            if (begin < index()) {
                shell_token token;
                token.index = begin;
                token.type = shell_token_type::literal;
                token.str = substr(begin, index() - begin);
                emplace_token(token);
            }

            add_token(shell_token_type::backtick_substitution_open);
            push_scope(shell_scope::backtick_substitution);
            break;
        } else if (c == '\\') {
            slash_count ^= 1;
        }
    }
}

void shell_tokenizer::tokenize_field()
{
    shell_token token;
    token.index = index();
    token.type = shell_token_type::field;

    // Find the end of this token by searching for a "known" character
    while (is_field_char(next()) && advance()) {}

    token.str = substr(token.index, index() - token.index + 1);
    emplace_token(token);
}

void shell_tokenizer::tokenize_redirection()
{
    shell_token token;
    token.index = index();
    token.type = shell_token_type::redirection;

    auto remaining_str = substr(index());

    re2::StringPiece redirection;
    const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
    if (re2::RE2::PartialMatch(ref, redirection_regex, &redirection)) {
        // At least one of the strings will contain a match
        if (!redirection.empty()) {
            token.str = substr(token.index, redirection.size());
            advance(token.str.size() - 1);
            emplace_token(token);
        }
    }
}

std::vector<shell_token> shell_tokenizer::tokenize()
{
    // The string is evaluated based on the current scope, if we're in the global
    // scope, i.e. the top-level command, the string just needs to tokenized,
    // however if the scope is a subcommand (command substitution, backtick
    // substution) the string must be tokenized whilst searching for the end of
    // the current subcommand. If we're inside a double quoted string, the
    // tokenization must attempt to find substitutions / expansions.
    push_scope(shell_scope::global);

    for (; !eof(); advance()) {
        if (current_scope_ == shell_scope::double_quoted_string) {
            tokenize_double_quoted_string_scope();
            continue;
        }

        auto c = peek();
        if (ddwaf::isspace(c)) {
            // Skip spaces
            while (ddwaf::isspace(next()) && advance()) {}
        } else if (c == '"') {
            add_token(shell_token_type::double_quoted_string_open);
            push_scope(shell_scope::double_quoted_string);

            // Skip "
            advance();
            // Tokenize the double quoted string, which might be interrupted
            // if there is a substitution / expansion
            tokenize_double_quoted_string_scope();
        } else if (c == '$') {
            auto n = next();
            // Tokenize:
            // - Command substitution $()
            // - Arithmetic expansion $(()) or $[]
            // - Variable $XYZ or ${XYZ}
            // - Special variable
            if (n == '(') {
                auto n2 = next(2);
                if (n2 == '(') {
                    // Arithmetic expansion
                    tokenize_delimited_token("))", shell_token_type::field);
                } else if (n2 == '<') {
                    // File redirection
                    tokenize_delimited_token(")", shell_token_type::field);
                } else {
                    add_token(shell_token_type::command_substitution_open, 2);
                    push_scope(shell_scope::command_substitution);
                    // advance();
                }
            } else if (n == '{' || ddwaf::isalnum(n) || n == '_' || n == '-' || n == '?' ||
                       n == '@' || n == '#' || n == '*' || n == '$' || n == '!') {
                tokenize_variable();
            } else if (n == '[') {
                // Legacy Arithmetic expansion
                tokenize_delimited_token("]", shell_token_type::field);
            }
        } else if (c == ')') {
            if (current_scope_ == shell_scope::command_substitution) {
                add_token(shell_token_type::command_substitution_close);
                pop_scope();
            } else if (current_scope_ == shell_scope::process_substitution) {
                add_token(shell_token_type::process_substitution_close);
                pop_scope();
            } else if (current_scope_ == shell_scope::subshell) {
                add_token(shell_token_type::subshell_close);
                pop_scope();
            } else {
                add_token(shell_token_type::parenthesis_close);
            }
        } else if (c == '`') {
            if (current_scope_ == shell_scope::backtick_substitution) {
                // End of the backtick command substitution, add a token for the
                // final backtick and exit the scope
                add_token(shell_token_type::backtick_substitution_close);

                pop_scope();
            } else {
                // Backtick substitution, add a token for the first backtick and
                // open a new scope
                add_token(shell_token_type::backtick_substitution_open);
                push_scope(shell_scope::backtick_substitution);
            }
        } else if (c == '(') {
            if (!tokens_.empty() && last_token_type() == shell_token_type::equal) {
                // Array
                tokenize_delimited_token(")", shell_token_type::field);
            } else if (next() == '(') {
                // Arithmetic expansions
                tokenize_delimited_token("))", shell_token_type::field);
            } else if (should_expect_subprocess()) {
                add_token(shell_token_type::subshell_open);
                push_scope(shell_scope::subshell);
            } else {
                add_token(shell_token_type::parenthesis_open);
            }
        } else if (c == '=') {
            add_token(shell_token_type::equal);
        } else if (c == '\n' || c == ';') {
            add_token(shell_token_type::control);
        } else if (c == '|') {
            add_token(shell_token_type::control, next() == '|' ? 2 : 1);
        } else if (c == '&') {
            auto n = next();
            if (n == '>') {
                tokenize_redirection();
            } else if (n == '&') {
                add_token(shell_token_type::control, 2);
            } else {
                add_token(shell_token_type::control);
            }
        } else if (c == '{') {
            auto n = next();
            if (n == ' ') {
                add_token(shell_token_type::compound_command_open);
                push_scope(shell_scope::compound_command);
            } else {
                add_token(shell_token_type::curly_brace_open);
            }
        } else if (c == '}') {
            if (current_scope_ == shell_scope::compound_command) {
                add_token(shell_token_type::compound_command_close);
                pop_scope();
            } else {
                add_token(shell_token_type::curly_brace_close);
            }
        } else if (c == '\'') {
            if (should_expect_definition_or_executable()) {
                tokenize_delimited_token("'", shell_token_type::executable);
            } else {
                tokenize_delimited_token("'", shell_token_type::single_quoted_string);
            }
        } else if (ddwaf::isdigit(c)) {
            auto n = next();
            if (n == '<' || n == '>') {
                tokenize_redirection();
            } else {
                tokenize_field();
            }
        } else if (c == '<' || c == '>') {
            auto n = next();
            if (n == '(') {
                add_token(shell_token_type::process_substitution_open, 2);
                push_scope(shell_scope::process_substitution);
            } else {
                tokenize_redirection();
            }
        } else {
            tokenize_field();
            if (!tokens_.empty() && should_expect_definition_or_executable()) {
                if (next() == '=') {
                    last_token().type = shell_token_type::variable_definition;
                } else {
                    last_token().type = shell_token_type::executable;
                }
            }
        }

        if (!tokens_.empty()) {
            auto type = last_token_type();
            if (type == shell_token_type::executable) {
                set_executable_found();
            } else if (type == shell_token_type::control) {
                reset_executable_found();
            }
        }
    }

    return tokens_;
}

} // namespace ddwaf
