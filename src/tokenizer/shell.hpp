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
        double_quoted_string,  // " ... "
        backtick_substitution, // ` ... `
        command_substitution,  // $( ... )
        compound_command,      // { ... }
        subshell,              // ( ... )
        process_substitution,  // <() or >()
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

    [[nodiscard]] bool should_expect_subprocess() const
    {
        if (tokens_.empty()) {
            return true;
        }

        auto t = current_token_type();
        return t == shell_token_type::control ||
               t == shell_token_type::backtick_substitution_open ||
               t == shell_token_type::command_substitution_open ||
               t == shell_token_type::process_substitution_open ||
               t == shell_token_type::compound_command_open;
    }

    [[nodiscard]] static bool token_allowed_before_executable(shell_token_type type)
    {
        return type == shell_token_type::control ||
               type == shell_token_type::backtick_substitution_open ||
               type == shell_token_type::command_substitution_open ||
               type == shell_token_type::process_substitution_open ||
               type == shell_token_type::compound_command_open ||
               type == shell_token_type::subshell_open || type == shell_token_type::whitespace;
    }

    void tokenize_single_quoted_string();
    void tokenize_double_quoted_string_scope();
    void tokenize_variable();
    void tokenize_field(shell_token_type type = shell_token_type::field);
    void tokenize_literal();
    void tokenize_redirection();
    void tokenize_delimited_token(std::string_view delimiter, shell_token_type type);
};

} // namespace ddwaf
