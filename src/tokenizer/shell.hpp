// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "tokenizer/base.hpp"
#include "utils.hpp"
#include <fmt/format.h>
#include <ostream>
#include <re2/re2.h>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace ddwaf {

enum class shell_token_type {
    unknown,
    executable,
    field,
    literal,
    double_quote,
    single_quote,
    control,
    variable_definition,
    variable,
    whitespace,
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
};

using shell_token = base_token<shell_token_type>;

std::ostream &operator<<(std::ostream &os, shell_token_type type);

class shell_tokenizer : protected base_tokenizer<shell_token_type> {
public:
    explicit shell_tokenizer(
        std::string_view str, std::unordered_set<shell_token_type> skip_tokens = {});

    void tokenize_single_quoted_string();
    void tokenize_double_quoted_string_scope();
    void tokenize_variable();
    void tokenize_field();
    void tokenize_literal();
    void tokenize_redirection();
    void tokenize_delimited_token(std::string_view delimiter, shell_token_type type);

    std::vector<shell_token> tokenize();

protected:
    static constexpr char IFS = ' ';

    enum class shell_scope {
        global,
        double_quoted_string,  // " ... "
        backtick_substitution, // ` ... `
        command_substitution,  // $( ... )
        // Unused
        command_grouping, // { ... }
        subshell,         // ( ... )
    };

    std::vector<shell_scope> scope_stack;

    friend std::ostream &operator<<(std::ostream &os, shell_scope scope);
};

} // namespace ddwaf
