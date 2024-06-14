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

TEST(TestShellTokenizer, TokenTypeOstream)
{
    auto stream_token = [](auto token) {
        std::stringstream ss;
        ss << token;
        return ss.str();
    };

    EXPECT_STR(stream_token(shell_token_type::unknown), "unknown");
    EXPECT_STR(stream_token(shell_token_type::executable), "executable");
    EXPECT_STR(stream_token(shell_token_type::field), "field");
    EXPECT_STR(stream_token(shell_token_type::literal), "literal");
    EXPECT_STR(
        stream_token(shell_token_type::double_quoted_string_open), "double_quoted_string_open");
    EXPECT_STR(
        stream_token(shell_token_type::double_quoted_string_close), "double_quoted_string_close");
    EXPECT_STR(stream_token(shell_token_type::single_quoted_string), "single_quoted_string");
    EXPECT_STR(stream_token(shell_token_type::control), "control");
    EXPECT_STR(stream_token(shell_token_type::variable_definition), "variable_definition");
    EXPECT_STR(stream_token(shell_token_type::variable), "variable");
    EXPECT_STR(stream_token(shell_token_type::equal), "equal");
    EXPECT_STR(
        stream_token(shell_token_type::backtick_substitution_open), "backtick_substitution_open");
    EXPECT_STR(
        stream_token(shell_token_type::backtick_substitution_close), "backtick_substitution_close");
    EXPECT_STR(stream_token(shell_token_type::dollar), "dollar");
    EXPECT_STR(stream_token(shell_token_type::redirection), "redirection");
    EXPECT_STR(
        stream_token(shell_token_type::command_substitution_open), "command_substitution_open");
    EXPECT_STR(
        stream_token(shell_token_type::command_substitution_close), "command_substitution_close");
    EXPECT_STR(stream_token(shell_token_type::parenthesis_open), "parenthesis_open");
    EXPECT_STR(stream_token(shell_token_type::parenthesis_close), "parenthesis_close");
    EXPECT_STR(stream_token(shell_token_type::curly_brace_open), "curly_brace_open");
    EXPECT_STR(stream_token(shell_token_type::curly_brace_close), "curly_brace_close");
    EXPECT_STR(
        stream_token(shell_token_type::process_substitution_open), "process_substitution_open");
    EXPECT_STR(
        stream_token(shell_token_type::process_substitution_close), "process_substitution_close");
    EXPECT_STR(stream_token(shell_token_type::subshell_open), "subshell_open");
    EXPECT_STR(stream_token(shell_token_type::subshell_close), "subshell_close");
    EXPECT_STR(stream_token(shell_token_type::compound_command_open), "compound_command_open");
    EXPECT_STR(stream_token(shell_token_type::compound_command_close), "compound_command_close");
}

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
        {R"(echo "stuff")", {stt::executable, stt::double_quoted_string_open, stt::literal,
                                stt::double_quoted_string_close}},
        {R"("var=2")",
            {stt::double_quoted_string_open, stt::literal, stt::double_quoted_string_close}},
        {R"(echo "literal $0")", {stt::executable, stt::double_quoted_string_open, stt::literal,
                                     stt::variable, stt::double_quoted_string_close}},
        {R"(echo "$0 literal")", {stt::executable, stt::double_quoted_string_open, stt::variable,
                                     stt::literal, stt::double_quoted_string_close}},
        {R"(echo "literal $0 literal")",
            {stt::executable, stt::double_quoted_string_open, stt::literal, stt::variable,
                stt::literal, stt::double_quoted_string_close}},
        {R"(echo "l$0")", {stt::executable, stt::double_quoted_string_open, stt::literal,
                              stt::variable, stt::double_quoted_string_close}},
        {R"(echo "$0l")", {stt::executable, stt::double_quoted_string_open, stt::variable,
                              stt::literal, stt::double_quoted_string_close}},
        {R"(echo "l$0l")", {stt::executable, stt::double_quoted_string_open, stt::literal,
                               stt::variable, stt::literal, stt::double_quoted_string_close}},
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
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"!(ls "$(ls -l)")!",
            {stt::executable, stt::double_quoted_string_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "literal $(ls -l)")!",
            {stt::executable, stt::double_quoted_string_open, stt::literal,
                stt::command_substitution_open, stt::executable, stt::field,
                stt::command_substitution_close, stt::double_quoted_string_close}},
        {R"!(ls "l$(ls -l)")!",
            {stt::executable, stt::double_quoted_string_open, stt::literal,
                stt::command_substitution_open, stt::executable, stt::field,
                stt::command_substitution_close, stt::double_quoted_string_close}},
        {R"!(ls "$(ls -l) literal")!",
            {stt::executable, stt::double_quoted_string_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close, stt::literal,
                stt::double_quoted_string_close}},
        {R"!(ls "$(ls -l)l")!",
            {stt::executable, stt::double_quoted_string_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close, stt::literal,
                stt::double_quoted_string_close}},
        {R"!(ls "literal $(ls -l) literal")!",
            {stt::executable, stt::double_quoted_string_open, stt::literal,
                stt::command_substitution_open, stt::executable, stt::field,
                stt::command_substitution_close, stt::literal, stt::double_quoted_string_close}},
        {R"!(ls "l$(ls -l)l")!",
            {stt::executable, stt::double_quoted_string_open, stt::literal,
                stt::command_substitution_open, stt::executable, stt::field,
                stt::command_substitution_close, stt::literal, stt::double_quoted_string_close}},
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

TEST(TestShellTokenizer, DoubleQuotedStringWithBacktickSubstitution)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"!(ls "`ls -l`")!",
            {stt::executable, stt::double_quoted_string_open, stt::backtick_substitution_open,
                stt::executable, stt::field, stt::backtick_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "literal `ls -l`")!",
            {stt::executable, stt::double_quoted_string_open, stt::literal,
                stt::backtick_substitution_open, stt::executable, stt::field,
                stt::backtick_substitution_close, stt::double_quoted_string_close}},
        {R"!(ls "l`ls -l`")!",
            {stt::executable, stt::double_quoted_string_open, stt::literal,
                stt::backtick_substitution_open, stt::executable, stt::field,
                stt::backtick_substitution_close, stt::double_quoted_string_close}},
        {R"!(ls "`ls -l` literal")!",
            {stt::executable, stt::double_quoted_string_open, stt::backtick_substitution_open,
                stt::executable, stt::field, stt::backtick_substitution_close, stt::literal,
                stt::double_quoted_string_close}},
        {R"!(ls "`ls -l`l")!",
            {stt::executable, stt::double_quoted_string_open, stt::backtick_substitution_open,
                stt::executable, stt::field, stt::backtick_substitution_close, stt::literal,
                stt::double_quoted_string_close}},
        {R"!(ls "literal `ls -l` literal")!",
            {stt::executable, stt::double_quoted_string_open, stt::literal,
                stt::backtick_substitution_open, stt::executable, stt::field,
                stt::backtick_substitution_close, stt::literal, stt::double_quoted_string_close}},
        {R"!(ls "l`ls -l`l")!",
            {stt::executable, stt::double_quoted_string_open, stt::literal,
                stt::backtick_substitution_open, stt::executable, stt::field,
                stt::backtick_substitution_close, stt::literal, stt::double_quoted_string_close}},
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

TEST(TestShellTokenizer, RedirectionTokens)
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

TEST(TestShellTokenizer, Redirections)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"ls > /tmp/test args", {stt::executable, stt::redirection, stt::field, stt::field}},
        {"ls args > /tmp/test", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls >                               /tmp/test args",
            {stt::executable, stt::redirection, stt::field, stt::field}},
        {"ls args 2> /tmp/test", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args >> /tmp/test", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args > /tmp/test 2> /etc/stderr", {stt::executable, stt::field, stt::redirection,
                                                   stt::field, stt::redirection, stt::field}},
        {"ls args>/tmp/test", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args < file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args<file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args <<< file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args << file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args <<- file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args <& file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args &> file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args <> file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args >| file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args <&1 file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0> file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0>> file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0< file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0<< file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0<& file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0<&- file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0<&1 file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0>& file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0>&1 file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0>&- file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0<<- file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0<> file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 0>| file", {stt::executable, stt::field, stt::redirection, stt::field}},
        // TODO invalid / seemingly redirections
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
        {"var=(1 2 3)", {stt::variable_definition, stt::equal, stt::field}},
        {"var=$(( 1+1 ))", {stt::variable_definition, stt::equal, stt::field}},
        {"var=$[ 1+1 ]", {stt::variable_definition, stt::equal, stt::field}},
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

TEST(TestShellTokenizer, Variable)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"echo ${var}", {stt::executable, stt::variable}},
        {"echo $var", {stt::executable, stt::variable}},
        {"echo ${var[@]}", {stt::executable, stt::variable}},
        {"echo $0", {stt::executable, stt::variable}},
        {"echo $1", {stt::executable, stt::variable}},
        {"echo $2", {stt::executable, stt::variable}},
        {"echo $3", {stt::executable, stt::variable}},
        {"echo $4", {stt::executable, stt::variable}},
        {"echo $5", {stt::executable, stt::variable}},
        {"echo $6", {stt::executable, stt::variable}},
        {"echo $7", {stt::executable, stt::variable}},
        {"echo $8", {stt::executable, stt::variable}},
        {"echo $9", {stt::executable, stt::variable}},
        {"echo $-", {stt::executable, stt::variable}},
        {"echo $#", {stt::executable, stt::variable}},
        {"echo $@", {stt::executable, stt::variable}},
        {"echo $?", {stt::executable, stt::variable}},
        {"echo $*", {stt::executable, stt::variable}},
        {"echo $$", {stt::executable, stt::variable}},
        {"echo $!", {stt::executable, stt::variable}},
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

TEST(TestShellTokenizer, MultipleCommands)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"true && echo \"hello\" | tr h '' | tr e a",
            {stt::executable, stt::control, stt::executable, stt::double_quoted_string_open,
                stt::literal, stt::double_quoted_string_close, stt::control, stt::executable,
                stt::field, stt::single_quoted_string, stt::control, stt::executable, stt::field,
                stt::field}},
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

TEST(TestShellTokenizer, ArithmeticExpansion)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{{"(( var=1+1 ))", {stt::field}}};

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
