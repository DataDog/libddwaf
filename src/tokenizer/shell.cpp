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
/*
 *  &>>?               # Matches &> and &>>
 *  |                  # OR
 *  (?:
 *      [0-9]*>        # Matches optional digits followed by >
 *      (?:
 *          \|         # Matches a |
 *          |          # OR
 *          >          # Matches a >
 *          |          # OR
 *          &[0-9]*-?  # Matches & followed by optional digits and an optional -
 *      )?
 *  )
 *  |                  # OR
 *  (?:
 *      [0-9]*<        # Matches optional digit followed by <
 *      (?:
 *          <(?:-|<)?  # Matches < optionally followed by - or <
 *          |          # OR
 *          &[0-9]*-?  # Matches & followed by optional digits and an optional -
 *          |          # OR
 *          >          # Matches a >
 *      )?
 *  )
 */
re2::RE2 redirection_regex(
    R"((&>>?|(?:[0-9]*>(?:\||>|&[0-9]*-?)?)|(?:[0-9]*<(?:<(?:-|<)?|&[0-9]*-?|>)?)))");

bool is_var_char(char c) { return ddwaf::isalnum(c) || c == '_'; }

bool is_field_char(char c)
{
    return c != '`' && c != '$' && c != '{' && c != '}' && c != '[' && c != ']' && c != '(' &&
           c != ')' && c != '\'' && c != '"' && c != '#' && c != '=' && c != '|' && c != '<' &&
           c != '>' && c != ';' && c != '&' && c != '\n' && c != '\t' && c != ' ';
}

bool is_space_char(char c) { return c == ' ' || c == '\t'; }

void find_executables_and_strip_whitespaces(std::vector<shell_token> &tokens)
{
    // The scope within the command, this helps identify high level constructs
    // which end up evaluating as part of a command, e.g. an executable
    // generated from a command substitution
    enum class command_scope {
        variable_definition_or_executable,
        variable_definition,
        arguments,
        none,
    };

    std::size_t read = 0;
    std::size_t write = 0;

    std::vector<command_scope> command_scope_stack{
        command_scope::variable_definition_or_executable};
    for (; read < tokens.size(); read++) {
        auto &token = tokens[read];
        auto &scope = command_scope_stack.back();

        switch (token.type) {
        case shell_token_type::backtick_substitution_open:
        case shell_token_type::command_substitution_open:
        case shell_token_type::process_substitution_open:
        case shell_token_type::compound_command_open:
        case shell_token_type::subshell_open:
            if (scope == command_scope::variable_definition_or_executable) {
                // These tokens have nested commands which will be interpreted
                // as the executable, so we can consider the executable of this
                // scope "found", albeit detections will rely on nested
                // executables, rather than considering this the executable.
                scope = command_scope::arguments;
            }
            command_scope_stack.emplace_back(command_scope::variable_definition_or_executable);
            break;
        case shell_token_type::backtick_substitution_close:
        case shell_token_type::command_substitution_close:
        case shell_token_type::process_substitution_close:
        case shell_token_type::compound_command_close:
        case shell_token_type::subshell_close:
            command_scope_stack.pop_back();
            break;
        case shell_token_type::variable_definition:
            if (scope == command_scope::variable_definition_or_executable) {
                scope = command_scope::variable_definition;
            }
            break;
        case shell_token_type::field:
        case shell_token_type::variable:
        case shell_token_type::single_quoted_string:
        case shell_token_type::double_quoted_string:
            if (scope == command_scope::variable_definition_or_executable) {
                token.type = shell_token_type::executable;
                scope = command_scope::arguments;
            }
            break;
        case shell_token_type::whitespace:
            if (scope == command_scope::variable_definition) {
                scope = command_scope::variable_definition_or_executable;
            }
            // Skip adding the whitespace
            continue;
        case shell_token_type::control:
            // Control commands reset the command scope
            scope = command_scope::variable_definition_or_executable;
            break;
        default:
            break;
        }
        tokens[write++] = token;
    }

    tokens.resize(write);
}

} // namespace

std::ostream &operator<<(std::ostream &os, shell_token_type type)
{
    switch (type) {
    case shell_token_type::unknown:
        os << "unknown";
        break;
    case shell_token_type::whitespace:
        os << "whitespace";
        break;
    case shell_token_type::executable:
        os << "executable";
        break;
    case shell_token_type::field:
        os << "field";
        break;
    case shell_token_type::arithmetic_expansion:
        os << "arithmetic_expansion";
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
    shell_scope_stack_.reserve(8);

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
    while (idx < delimiter.size() && advance()) { idx = (peek() == delimiter[idx] ? idx + 1 : 0); }

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
    auto c = peek();
    if (c == '-' || c == '?' || c == '@' || c == '#' || c == '*' || c == '$' || c == '!' ||
        ddwaf::isdigit(c)) {
        // Special variable, these are one character long + dollar
        token.str = substr(token.index, 2);
    } else if (c == '{') {
        while (advance() && peek() != '}') {}
        token.str = substr(token.index, index() - token.index + 1);
    } else { // alphanumeric and underscores
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
    for (; !eof(); advance()) {
        auto c = peek();
        if (c == '"' && slash_count == 0) {
            pop_shell_scope();

            // At this point we know there's at least one token so no need to check
            auto &token = current_token();
            if (token.type == shell_token_type::double_quoted_string_open) {
                token.type = shell_token_type::double_quoted_string;
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
            auto n2 = next(2);
            if (n == '(' && n2 != '(' && n2 != '<') {
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
                push_shell_scope(shell_scope::command_substitution);
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
            push_shell_scope(shell_scope::backtick_substitution);
            break;
        } else if (c == '\\') {
            slash_count ^= 1;
        }
    }
}

void shell_tokenizer::tokenize_field(shell_token_type type)
{
    shell_token token;
    token.index = index();
    token.type = type;

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

void shell_tokenizer::tokenize_redirection_or_field()
{
    shell_token token;
    token.index = index();

    auto n = next();
    // The first character is a digit, check if there are others
    while (ddwaf::isdigit(n) && advance()) { n = next(); }

    // We have exited, either because we reached the end of the string or because
    // the next character is not a digit
    if (eof()) {
        // We found a long number at the end of the resource
        token.type = shell_token_type::field;
        token.str = substr(token.index, index() - token.index + 1);
        emplace_token(token);
    } else if (n == '>' || n == '<') {
        advance(); // Skip that current digit
        auto remaining_str = substr(index());

        re2::StringPiece redirection;
        const re2::StringPiece ref(remaining_str.data(), remaining_str.size());
        if (re2::RE2::PartialMatch(ref, redirection_regex, &redirection)) {
            // At least one of the strings will contain a match
            if (!redirection.empty()) {
                token.type = shell_token_type::redirection;
                token.str = substr(token.index, index() - token.index + redirection.size());
                advance(redirection.size());
                emplace_token(token);
            }
        }
    } else {
        token.type = shell_token_type::field;

        // Find the end of this token by searching for a "known" character
        while (is_field_char(next()) && advance()) {}

        token.str = substr(token.index, index() - token.index + 1);
        emplace_token(token);
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
    push_shell_scope(shell_scope::global);

    for (; !eof(); advance()) {
        if (current_shell_scope_ == shell_scope::double_quoted_string) {
            tokenize_double_quoted_string_scope();
            continue;
        }

        auto c = peek();
        if (is_space_char(c)) {
            shell_token token;
            token.index = index();
            token.type = shell_token_type::whitespace;

            while (is_space_char(next()) && advance()) {}

            token.str = substr(token.index, index() - token.index + 1);
            emplace_token(token);
        } else if (c == '"') {
            add_token(shell_token_type::double_quoted_string_open);
            push_shell_scope(shell_scope::double_quoted_string);

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
                    tokenize_delimited_token("))", shell_token_type::arithmetic_expansion);
                } else if (n2 == '<') {
                    // File redirection
                    tokenize_delimited_token(")", shell_token_type::field);
                } else {
                    add_token(shell_token_type::command_substitution_open, 2);
                    push_shell_scope(shell_scope::command_substitution);
                }
            } else if (n == '{' || ddwaf::isalnum(n) || n == '_' || n == '-' || n == '?' ||
                       n == '@' || n == '#' || n == '*' || n == '$' || n == '!') {
                tokenize_variable();
            } else if (n == '[') {
                // Legacy Arithmetic expansion
                tokenize_delimited_token("]", shell_token_type::arithmetic_expansion);
            }
        } else if (c == ')') {
            if (current_shell_scope_ == shell_scope::command_substitution) {
                add_token(shell_token_type::command_substitution_close);
                pop_shell_scope();
            } else if (current_shell_scope_ == shell_scope::process_substitution) {
                add_token(shell_token_type::process_substitution_close);
                pop_shell_scope();
            } else if (current_shell_scope_ == shell_scope::subshell) {
                add_token(shell_token_type::subshell_close);
                pop_shell_scope();
            } else {
                add_token(shell_token_type::parenthesis_close);
            }
        } else if (c == '`') {
            if (current_shell_scope_ == shell_scope::backtick_substitution) {
                // End of the backtick command substitution, add a token for the
                // final backtick and exit the scope
                add_token(shell_token_type::backtick_substitution_close);

                pop_shell_scope();
            } else {
                // Backtick substitution, add a token for the first backtick and
                // open a new scope
                add_token(shell_token_type::backtick_substitution_open);
                push_shell_scope(shell_scope::backtick_substitution);
            }
        } else if (c == '(') {
            if (!tokens_.empty() && current_token_type() == shell_token_type::equal) {
                // Array
                tokenize_delimited_token(")", shell_token_type::field);
            } else if (next() == '(') {
                // Arithmetic expansions
                tokenize_delimited_token("))", shell_token_type::arithmetic_expansion);
            } else if (should_expect_subprocess()) {
                add_token(shell_token_type::subshell_open);
                push_shell_scope(shell_scope::subshell);
            } else {
                add_token(shell_token_type::parenthesis_open);
            }
        } else if (c == '=') {
            add_token(shell_token_type::equal);
        } else if (c == '\n' || c == ';' || c == '!') {
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
                // Swallow the whitespace
                advance();
                push_shell_scope(shell_scope::compound_command);
            } else {
                add_token(shell_token_type::curly_brace_open);
            }
        } else if (c == '}') {
            if (current_shell_scope_ == shell_scope::compound_command) {
                add_token(shell_token_type::compound_command_close);
                pop_shell_scope();
            } else {
                add_token(shell_token_type::curly_brace_close);
            }
        } else if (c == '\'') {
            tokenize_delimited_token("'", shell_token_type::single_quoted_string);
        } else if (ddwaf::isdigit(c)) {
            tokenize_redirection_or_field();
        } else if (c == '<' || c == '>') {
            auto n = next();
            if (n == '(') {
                add_token(shell_token_type::process_substitution_open, 2);
                push_shell_scope(shell_scope::process_substitution);
            } else {
                tokenize_redirection();
            }
        } else {
            tokenize_field();
            if (next() == '=') {
                current_token().type = shell_token_type::variable_definition;
            }
        }
    }

    find_executables_and_strip_whitespaces(tokens_);
    return tokens_;
}

} // namespace ddwaf
