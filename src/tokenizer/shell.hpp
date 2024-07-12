// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "tokenizer/base.hpp"
#include <fmt/format.h>
#include <ostream>
#include <re2/re2.h>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace ddwaf {

enum class shell_token_type {
    unknown,
    whitespace,
    executable,
    field,
    arithmetic_expansion,
    arithmetic_expansion_open,
    arithmetic_expansion_close,
    literal,
    double_quoted_string_open,
    double_quoted_string_close,
    double_quoted_string,
    single_quoted_string,
    control,
    variable_definition,
    variable,
    equal,
    backtick_substitution_open,
    backtick_substitution_close,
    dollar,
    redirection,
    command_substitution_open,
    command_substitution_close,
    parenthesis_open,
    parenthesis_close,
    curly_brace_open,
    curly_brace_close,
    process_substitution_open,
    process_substitution_close,
    subshell_open,
    subshell_close,
    compound_command_open,
    compound_command_close,
    array_open,
    array_close,
    parameter_expansion_open,
    parameter_expansion_close,
    file_redirection_open,
    file_redirection_close,
};

using shell_token = base_token<shell_token_type>;

std::ostream &operator<<(std::ostream &os, shell_token_type type);

class shell_tokenizer : protected base_tokenizer<shell_token_type> {
public:
    explicit shell_tokenizer(
        std::string_view str, std::unordered_set<shell_token_type> skip_tokens = {});

    std::vector<shell_token> tokenize();

protected:
    enum class shell_scope {
        global,
        double_quoted_string,        // " ... "
        backtick_substitution,       // ` ... `
        command_substitution,        // $( ... )
        compound_command,            // { ... }
        subshell,                    // ( ... )
        process_substitution,        // <() or >()
        legacy_arithmetic_expansion, // $[]
        arithmetic_expansion,        // (()) or $(( ))
        array,                       // =()
        file_redirection,            // $(< )
        parameter_expansion,         // ${}
    };

    std::vector<shell_scope> shell_scope_stack_;
    shell_scope current_shell_scope_{shell_scope::global};

    void push_shell_scope(shell_scope scope)
    {
        current_shell_scope_ = scope;

        shell_scope_stack_.emplace_back(scope);
    }

    void pop_shell_scope()
    {
        shell_scope_stack_.pop_back();
        current_shell_scope_ = shell_scope_stack_.back();
    }

    shell_token_type current_token_type() const { return tokens_.back().type; }

    shell_token &current_token() { return tokens_.back(); }

    [[nodiscard]] static bool token_allowed_before_executable(shell_token_type type)
    {
        return type == shell_token_type::control ||
               type == shell_token_type::backtick_substitution_open ||
               type == shell_token_type::command_substitution_open ||
               type == shell_token_type::process_substitution_open ||
               type == shell_token_type::compound_command_open ||
               type == shell_token_type::subshell_open || type == shell_token_type::whitespace;
    }

    template <typename T, typename... Rest>
    bool match_nth_nonws_token_descending(std::size_t n, T expected, Rest... args) const
    {
        const auto &nth_token = tokens_[n];
        if (nth_token.type == shell_token_type::whitespace) {
            return n > 0 && match_nth_nonws_token_descending(n - 1, expected, args...);
        }
        bool res = false;
        if constexpr (std::is_same_v<T, shell_token_type>) {
            res = (nth_token.type == expected);
        }
        if constexpr (std::is_same_v<T, std::string_view>) {
            res = (nth_token.str == expected);
        }
        if constexpr (sizeof...(args) > 0) {
            return n > 0 && res && match_nth_nonws_token_descending(n - 1, args...);
        } else {
            return res;
        }
    }
    // Match each provided token or string with the relevant token or string
    // starting from the end of the token array, ignoring whitespaces:
    // - args[0] == tokens_[last]
    // - args[1] == tokens_[last - 1]
    template <typename... Args> bool match_last_n_nonws_tokens(Args... args) const
    {
        if (tokens_.size() < sizeof...(Args)) {
            return false;
        }

        return match_nth_nonws_token_descending(tokens_.size() - 1, args...);
    }

    template <typename T, typename... Rest>
    bool match_last_nonws_token_with_one_of_T(
        const shell_token &obtained, T expected, Rest... args) const
    {
        bool res = false;
        if constexpr (std::is_same_v<T, shell_token_type>) {
            res = (obtained.type == expected);
        }
        if constexpr (std::is_same_v<T, std::string_view>) {
            res = (obtained.str == expected);
        }

        if constexpr (sizeof...(args) > 0) {
            return res || match_last_nonws_token_with_one_of_T(obtained, args...);
        } else {
            return res;
        }
    }

    template <typename... Args> bool match_last_nonws_token_with_one_of(Args... args) const
    {
        auto last_it = tokens_.rbegin();
        if (last_it != tokens_.rend() && last_it->type == shell_token_type::whitespace) {
            // Whitespaces are grouped together, so only one token can be expected
            ++last_it;
        }

        if (last_it == tokens_.rend()) {
            return false;
        }

        return match_last_nonws_token_with_one_of_T(*last_it, args...);
    }

    bool is_beginning_of_command()
    {
        return tokens_.empty() || match_last_nonws_token_with_one_of(shell_token_type::control,
                                      shell_token_type::backtick_substitution_open,
                                      shell_token_type::command_substitution_open,
                                      shell_token_type::process_substitution_open,
                                      shell_token_type::compound_command_open,
                                      shell_token_type::subshell_open, shell_token_type::control);
    }

    void tokenize_single_quoted_string();
    void tokenize_expandable_scope(std::string_view delimiter, shell_token_type full_token,
        shell_token_type open_token, shell_token_type close_token);
    void tokenize_variable();
    void tokenize_parameter_expansion();
    void tokenize_field(shell_token_type type = shell_token_type::field);
    void tokenize_literal();
    void tokenize_redirection();
    void tokenize_redirection_or_field();
    void tokenize_delimited_token(std::string_view delimiter, shell_token_type type);
};

} // namespace ddwaf
