// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "tokenizer/shell.hpp"
#include "log.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {
re2::RE2 redirection_regex(R"((&>>?|(?:[0-9]?>(?:\||>|&[0-9]?-?)?)|(?:[0-9]?<(?:<(?:-|<)?|&[0-9]?-?|>)?)))");

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
    case shell_scope::command_grouping:
        os << "command_grouping";
        break;
    case shell_scope::subshell:
        os << "subshell";
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
    case shell_token_type::double_quote:
        os << "double_quote";
        break;
    case shell_token_type::single_quote:
        os << "single_quote";
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
    case shell_token_type::whitespace:
        os << "whitespace";
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
    }
    return os;
}

shell_tokenizer::shell_tokenizer(std::string_view str, std::unordered_set<shell_token_type> skip_tokens): base_tokenizer(str, std::move(skip_tokens))
{
    if (!redirection_regex.ok()) {
        throw std::runtime_error(
            "redirection regex not valid: " + redirection_regex.error_arg());
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

void shell_tokenizer::tokenize_single_quoted_string()
{
    // Find the final single quote
    while (advance() && peek() != '\'') {}

    shell_token token;
    token.index = index();
    token.type = shell_token_type::single_quote;
    token.str = substr(token.index, index() - token.index + 1);
    emplace_token(token);
}

void shell_tokenizer::tokenize_variable()
{
    shell_token token;
    token.index = index();
    token.type = shell_token_type::variable;

    // Skip dollar
    advance();

    // We know the first character is $
    auto c = next();
    if (c == '-' || c == '?' || c == '@' || c == '#' || c == '*' || c == '$' || c == '!' ||
        ddwaf::isdigit(c)) {
        // Special variable, these are one character long + dollar
        token.str = substr(token.index, 2);
    } else {
        // TODO variables can contain the following characters: [a-zA-Z_]{1,}[a-zA-Z0-9_]{0,}
        // If the next element is a bracket, find the last bracket, otherwise find IFS
        auto expected_end = c == '{' ? '}' : IFS;
        while (advance() && peek() != expected_end) {}
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
    do {
        auto c = peek();
        if (c == '"' && slash_count == 0) {
            if (begin < index() - 1) {
                shell_token token;
                token.index = begin;
                token.type = shell_token_type::literal;
                token.str = substr(begin, index() - begin);
                emplace_token(token);
            }

            add_token(shell_token_type::double_quote);
            break;
        }

        if (c == '$' && slash_count == 0) {
            auto n = next();
            if (n == '(' && next(2) != '(') {
                // Command substitution, we add a field for the current string
                // contents, update the scope and exit. Note that we skip
                // arithmetic expansions
                if (begin < index() - 1) {
                    shell_token token;
                    token.index = begin;
                    token.type = shell_token_type::literal;
                    token.str = substr(begin, index() - begin);
                    emplace_token(token);
                }

                add_token(shell_token_type::command_substitution_open, 2);
                scope_stack.emplace_back(shell_scope::command_substitution);
                break;
            }

            if (n == '{' || ddwaf::isalnum(n) || n == '_' || n == '-' || n == '?' || n == '@' ||
                n == '#' || n == '*' || n == '$' || n == '!') {
                // Variable expansion, we tokenize it and continue
                add_token(shell_token_type::field, index() - begin);
                tokenize_variable();

                // We're still in the string so we can continue
                begin = index();
                continue;
            }

            // Other interesting cases are $[] which is an ancient syntax used for arithmetic,
            // equivalent to $(( ... )), but we don't care about these expansions.

            // Any other variant should be considered part of a literal
        } else if (c == '`') {
            // Backtick substitution, we add a literal for the current string
            // contents, update the scope and exit
            if (begin < index() - 1) {
                shell_token token;
                token.index = begin;
                token.type = shell_token_type::literal;
                token.str = substr(begin, index() - begin);
                emplace_token(token);
            }

            add_token(shell_token_type::backtick_substitution_open);

            scope_stack.emplace_back(shell_scope::backtick_substitution);
            break;
        } else if (c == '\\') {
            slash_count ^= 1;
        }
    } while (advance());
}

void shell_tokenizer::tokenize_field()
{
    // TODO add user-provided IFS?
    static constexpr std::string_view known_chars = "`${}[]()'\"#=|<>;&\n ";

    shell_token token;
    token.index = index();
    token.type = shell_token_type::field;

    // Find the end of this token by searching for a "known" character
    while (known_chars.find(next()) == std::string_view::npos && advance()) {}

    token.str = substr(token.index, index() - token.index);
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
        }
        emplace_token(token);
    }
}

std::vector<shell_token> shell_tokenizer::tokenize()
{
    // IFS should be user-provided when tokenizing
    scope_stack.reserve(8);
    scope_stack.emplace_back(shell_scope::global);

    // The string is evaluated based on the current scope, if we're in the global
    // scope, i.e. the top-level command, the string just needs to tokenized,
    // however if the scope is a subcommand (command substitution, backtick
    // substution) the string must be tokenized whilst searching for the end of
    // the current subcommand. If we're inside a double quoted string, the
    // tokenization must attempt to find substitutions / expansions.
    shell_scope current_scope = scope_stack.back();
    for (; !eof(); advance()) {

        if (current_scope == shell_scope::double_quoted_string) {
            tokenize_double_quoted_string_scope();
            // Update the scope, as we might be back at the global scope or at
            // another scope within the string (expansion, substitution)
            current_scope = scope_stack.back();
            continue;
        }

        auto c = peek();
        if (c == '"') {
            add_token(shell_token_type::double_quote);
            scope_stack.emplace_back(shell_scope::double_quoted_string);

            // Skip "
            advance();
            // Tokenize the double quoted string, which might be interrupted
            // if there is a substitution / expansion
            tokenize_double_quoted_string_scope();

            // Update the scope, as we might be back at the global scope or at
            // another scope within the string (expansion, substitution)
            current_scope = scope_stack.back();

        } else if (c == '$') {
            auto n = next();
            // Tokenize:
            // - Command substitution $()
            // - Arithmetic expansion $(()) or $[]
            // - Variable $XYZ or ${XYZ}
            // - Special variable
            if (n == '(') {
                auto n2 = next(2);
                // TODO: Handle file redirection $(<file)
                if (n2 == '(') {
                    // Arithmetic expansion
                    tokenize_delimited_token("))", shell_token_type::field);
                } else {
                    add_token(shell_token_type::command_substitution_open, 2);
                    scope_stack.emplace_back(shell_scope::command_substitution);
                    current_scope = shell_scope::command_substitution;
                    advance();
                }
            } else if (n == '{' || ddwaf::isalnum(n) || n == '_' || n == '-' || n == '?' ||
                       n == '@' || n == '#' || n == '*' || n == '$' || n == '!') {
                tokenize_variable();
            } else if (n == '[') {
                // Legacy Arithmetic expansion
                tokenize_delimited_token("]", shell_token_type::field);
            }
        } else if (c == ')') {
            if (current_scope == shell_scope::command_substitution) {
                add_token(shell_token_type::command_substitution_close);

                scope_stack.pop_back();
                current_scope = scope_stack.back();
            } else {
                add_token(shell_token_type::parenthesis_close);
            }
        } else if (c == '`') {
            if (current_scope == shell_scope::backtick_substitution) {
                // End of the backtick command substitution, add a token for the
                // final backtick and exit the scope
                add_token(shell_token_type::backtick_substitution_close);

                scope_stack.pop_back();
                current_scope = scope_stack.back();
            } else {
                // Backtick substitution, add a token for the first backtick and
                // open a new scope
                add_token(shell_token_type::backtick_substitution_open);
                scope_stack.emplace_back(shell_scope::backtick_substitution);
                current_scope = scope_stack.back();
            }
        } else if (c == IFS) {
            shell_token token;
            token.index = index();
            token.type = shell_token_type::whitespace;

            // Skip IFS
            while (next() == IFS && advance()) {}

            token.str = substr(token.index, index() - token.index);
            emplace_token(token);
        } else if (c == '(') {
            add_token(shell_token_type::parenthesis_open);
        } else if (c == ')') {
            add_token(shell_token_type::parenthesis_close);
        } else if (c == '=') {
            add_token(shell_token_type::equal);
        } else if (c == '\n' || c == ';' || c == '|') {
            add_token(shell_token_type::control);
        } else if (c == '&') {
            auto n = next();
            if (n == '>') {
                tokenize_redirection();
            } else {
                add_token(shell_token_type::control);
            }
        } else if (c == '{') {
            add_token(shell_token_type::curly_brace_open);
        } else if (c == '}') {
            add_token(shell_token_type::curly_brace_close);
        } else if (c == '\'') {
            tokenize_single_quoted_string();
        } else if (ddwaf::isdigit(c)) {
            auto n = next();
            if (n == '<' || n == '>') {
                tokenize_redirection();
            } else {
                tokenize_field();
            }
        } else if (c == '<' || c == '>') {
            tokenize_redirection();
        } else {
            tokenize_field();
        }
    }

    std::vector<shell_token_type> token_stack;
    token_stack.reserve(8);

    std::vector<shell_token> final_tokens;
    final_tokens.reserve(tokens_.size());

    token_stack.emplace_back(shell_token_type::variable_definition);

    // Remove whitespaces, identify
    for (std::size_t i = 0; i < tokens_.size(); ++i) {
        auto token = tokens_[i];
        if (token.type == shell_token_type::double_quote) {
            if (token_stack.back() == shell_token_type::double_quote) {
                token_stack.pop_back();
                if (token_stack.back() == shell_token_type::variable_definition) {
                    if (!final_tokens.empty()) {
                        final_tokens.back().type = shell_token_type::executable;
                    }
                    token_stack.pop_back();
                }
            } else {
                token_stack.emplace_back(token.type);
            }
        } else if (token.type == shell_token_type::single_quote) {
            if (token_stack.back() == shell_token_type::single_quote) {
                token_stack.pop_back();
            } else {
                token_stack.emplace_back(token.type);
            }
        } else if (token.type == shell_token_type::backtick_substitution_open ||
                token.type == shell_token_type::command_substitution_open ||
                token.type == shell_token_type::control ||
                token_stack.back() == shell_token_type::equal) {
            token_stack.back() = shell_token_type::variable_definition;
        } else if (token_stack.back() == shell_token_type::variable_definition) {
            if (token.type == shell_token_type::field || token.type == shell_token_type::variable) {
                if ((i + 1) < tokens_.size() && tokens_[i + 1].type == shell_token_type::equal) {
                    auto new_token = token;
                    new_token.type = shell_token_type::variable_definition;
                    final_tokens.emplace_back(new_token);
                    final_tokens.emplace_back(tokens_[++i]);
                    token_stack.back() = shell_token_type::equal;
                    continue;
                }

                if (final_tokens.empty() || final_tokens.back().type != shell_token_type::redirection) {
                    token.type = shell_token_type::executable;
                    token_stack.back() = shell_token_type::unknown;
                }
            }
        }

        if (token.type != shell_token_type::whitespace) {
            final_tokens.emplace_back(token);
        }
    }

    return final_tokens;
}

} // namespace ddwaf
