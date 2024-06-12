// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test_utils.hpp"
#include "tokenizer/shell.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
using stt = shell_token_type;

TEST(TestShellTokenizer, Basic)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"echo", {stt::executable}},
        {"echo    ", {stt::executable}},
        {"test echo", {stt::executable, stt::field}},
        {"ls -l", {stt::executable, stt::field}},
        {"ls dir1 dir2", {stt::executable, stt::field, stt::field}},
    };

    for (const auto &[input, expected_tokens] : samples) {
        shell_tokenizer tokenizer(input);

        auto tokens = tokenizer.tokenize();
        ASSERT_EQ(tokens.size(), expected_tokens.size()) << input;

        for (std::size_t i = 0; i < tokens.size(); ++i) {
            EXPECT_EQ(tokens[i].type, expected_tokens[i]) << input;
        }
    }
}

TEST(TestShellTokenizer, BasicDoubleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"echo \"stuff\"", {stt::executable, stt::double_quoted_string_open, stt::literal,
                               stt::double_quoted_string_close}},
        {"\"var=2\"",
            {stt::double_quoted_string_open, stt::literal, stt::double_quoted_string_close}},
    };

    for (const auto &[input, expected_tokens] : samples) {
        shell_tokenizer tokenizer(input);

        auto tokens = tokenizer.tokenize();
        ASSERT_EQ(tokens.size(), expected_tokens.size()) << input;

        for (std::size_t i = 0; i < tokens.size(); ++i) {
            EXPECT_EQ(tokens[i].type, expected_tokens[i]) << input;
        }
    }
}

TEST(TestShellTokenizer, DoubleQuotedStringWithCommandSubstitution)
{
    shell_tokenizer tokenizer("ls \"$(ls -l)\"");

    auto tokens = tokenizer.tokenize();
    EXPECT_EQ(tokens.size(), 7);
    EXPECT_EQ(tokens[0].type, stt::executable);
    EXPECT_EQ(tokens[1].type, stt::double_quoted_string_open);
    EXPECT_EQ(tokens[2].type, stt::command_substitution_open);
    EXPECT_EQ(tokens[3].type, stt::executable);
    EXPECT_EQ(tokens[4].type, stt::field);
    EXPECT_EQ(tokens[5].type, stt::command_substitution_close);
    EXPECT_EQ(tokens[6].type, stt::double_quoted_string_close);
}

TEST(TestShellTokenizer, DoubleQuotedStringWithBacktickSubstitution)
{
    shell_tokenizer tokenizer("ls \"`ls -l`\"");

    auto tokens = tokenizer.tokenize();
    EXPECT_EQ(tokens.size(), 7);
    EXPECT_EQ(tokens[0].type, stt::executable);
    EXPECT_EQ(tokens[1].type, stt::double_quoted_string_open);
    EXPECT_EQ(tokens[2].type, stt::backtick_substitution_open);
    EXPECT_EQ(tokens[3].type, stt::executable);
    EXPECT_EQ(tokens[4].type, stt::field);
    EXPECT_EQ(tokens[5].type, stt::backtick_substitution_close);
    EXPECT_EQ(tokens[6].type, stt::double_quoted_string_close);
}

TEST(TestShellTokenizer, Executable)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"echo", {stt::executable}},
        {"test echo", {stt::executable, stt::field}},
        {"{ echo; }", {stt::compound_command_open, stt::executable, stt::control,
                          stt::compound_command_close}},
        {"(ls -l)", {stt::subshell_open, stt::executable, stt::field, stt::subshell_close}},
        {"$(ls -l)", {stt::command_substitution_open, stt::executable, stt::field,
                         stt::command_substitution_close}},
        {"diff <(ls -l)", {stt::executable, stt::process_substitution_open, stt::executable,
                              stt::field, stt::process_substitution_close}},
        {"diff >(ls -l)", {stt::executable, stt::process_substitution_open, stt::executable,
                              stt::field, stt::process_substitution_close}},
    };

    for (const auto &[input, expected_tokens] : samples) {
        shell_tokenizer tokenizer(input);

        auto tokens = tokenizer.tokenize();
        ASSERT_EQ(tokens.size(), expected_tokens.size()) << input;

        for (std::size_t i = 0; i < tokens.size(); ++i) {
            EXPECT_EQ(tokens[i].type, expected_tokens[i]) << input;
        }
    }
}

TEST(TestShellTokenizer, Pipe)
{
    shell_tokenizer tokenizer("ls | cat");

    auto tokens = tokenizer.tokenize();
    EXPECT_EQ(tokens.size(), 3);
    EXPECT_EQ(tokens[0].type, stt::executable);
    EXPECT_EQ(tokens[1].type, stt::control);
    EXPECT_EQ(tokens[2].type, stt::executable);
}

TEST(TestShellTokenizer, CommandSequence)
{
    shell_tokenizer tokenizer("ls ; cat");

    auto tokens = tokenizer.tokenize();
    EXPECT_EQ(tokens.size(), 3);
    EXPECT_EQ(tokens[0].type, stt::executable);
    EXPECT_EQ(tokens[1].type, stt::control);
    EXPECT_EQ(tokens[2].type, stt::executable);
}

TEST(TestShellTokenizer, Redirections)
{
    std::vector<std::string> samples{"&>>", "1>", ">", ">>", ">|", ">&", "1>&", "1>&2", "1>&2-",
        "1>&-", "<", "1<", "2<&", "2<<", "2<<-", "<<-", "<<", "<<<", "1<<<", "1<&", "1<", "<&",
        "1<>", "<>"};

    for (const auto &sample : samples) {
        shell_tokenizer tokenizer(sample);
        auto tokens = tokenizer.tokenize();
        EXPECT_EQ(tokens.size(), 1);
        EXPECT_EQ(tokens[0].type, stt::redirection);
        EXPECT_STRV(tokens[0].str, sample.c_str());
    }
}

TEST(TestShellTokenizer, VariableDefinition)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"var=2", {stt::variable_definition, stt::equal, stt::field}},
        {"var=2; var=3", {stt::variable_definition, stt::equal, stt::field, stt::control,
                             stt::variable_definition, stt::equal, stt::field}},
        {"{ var=2; }", {stt::compound_command_open, stt::variable_definition, stt::equal,
                           stt::field, stt::control, stt::compound_command_close}},
        {"`var=2`", {stt::backtick_substitution_open, stt::variable_definition, stt::equal,
                        stt::field, stt::backtick_substitution_close}},
        {"(var=2)", {stt::subshell_open, stt::variable_definition, stt::equal, stt::field,
                        stt::subshell_close}},
        {"$(var=2)", {stt::command_substitution_open, stt::variable_definition, stt::equal,
                         stt::field, stt::command_substitution_close}},
        {"<(var=2)", {stt::process_substitution_open, stt::variable_definition, stt::equal,
                         stt::field, stt::process_substitution_close}},
        {">(var=2)", {stt::process_substitution_open, stt::variable_definition, stt::equal,
                         stt::field, stt::process_substitution_close}},
    };

    for (const auto &[input, expected_tokens] : samples) {
        shell_tokenizer tokenizer(input);

        auto tokens = tokenizer.tokenize();
        ASSERT_EQ(tokens.size(), expected_tokens.size()) << input;

        for (std::size_t i = 0; i < tokens.size(); ++i) {
            EXPECT_EQ(tokens[i].type, expected_tokens[i]) << input;
        }
    }
}

} // namespace
