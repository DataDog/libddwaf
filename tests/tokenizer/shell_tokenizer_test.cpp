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
    EXPECT_STR(stream_token(shell_token_type::whitespace), "whitespace");
    EXPECT_STR(stream_token(shell_token_type::executable), "executable");
    EXPECT_STR(stream_token(shell_token_type::field), "field");
    EXPECT_STR(stream_token(shell_token_type::arithmetic_expansion), "arithmetic_expansion");
    EXPECT_STR(
        stream_token(shell_token_type::double_quoted_string_open), "double_quoted_string_open");
    EXPECT_STR(
        stream_token(shell_token_type::double_quoted_string_close), "double_quoted_string_close");
    EXPECT_STR(stream_token(shell_token_type::double_quoted_string), "double_quoted_string");
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
    EXPECT_STR(
        stream_token(shell_token_type::arithmetic_expansion_open), "arithmetic_expansion_open");
    EXPECT_STR(
        stream_token(shell_token_type::arithmetic_expansion_close), "arithmetic_expansion_close");
    EXPECT_STR(stream_token(shell_token_type::array_open), "array_open");
    EXPECT_STR(stream_token(shell_token_type::array_close), "array_close");
    EXPECT_STR(
        stream_token(shell_token_type::parameter_expansion_open), "parameter_expansion_open");
    EXPECT_STR(
        stream_token(shell_token_type::parameter_expansion_close), "parameter_expansion_close");
    EXPECT_STR(stream_token(shell_token_type::file_redirection_open), "file_redirection_open");
    EXPECT_STR(stream_token(shell_token_type::file_redirection_close), "file_redirection_close");
}

TEST(TestShellTokenizer, Basic)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"echo", {stt::executable}},
        {"$(<file)", {stt::redirection}},
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

// TODO a double quoted string can be considered an executable
TEST(TestShellTokenizer, DoubleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(echo "stuff")", {stt::executable, stt::double_quoted_string}},
        {R"(echo "var=2")", {stt::executable, stt::double_quoted_string}},
        {R"(echo "literal $0")", {stt::executable, stt::double_quoted_string}},
        {R"(echo "$0 literal")", {stt::executable, stt::double_quoted_string}},
        {R"(echo "literal $0 literal")", {stt::executable, stt::double_quoted_string}},
        {R"(echo "l$0")", {stt::executable, stt::double_quoted_string}},
        {R"(echo "$0l")", {stt::executable, stt::double_quoted_string}},
        {R"(echo "l$0l")", {stt::executable, stt::double_quoted_string}},
        {R"("stuff")", {stt::executable}},
        {R"("var=2")", {stt::executable}},
        {R"!("$(( 1+1 ))")!", {stt::double_quoted_string_open, stt::arithmetic_expansion,
                                  stt::double_quoted_string_close}},
        {R"!("$[ 1+1 ]")!", {stt::double_quoted_string_open, stt::arithmetic_expansion,
                                stt::double_quoted_string_close}},
        {R"!("$(<file)")!",
            {stt::double_quoted_string_open, stt::redirection, stt::double_quoted_string_close}},
        {R"!("$(( $(echo value) ))")!",
            {stt::double_quoted_string_open, stt::arithmetic_expansion_open,
                stt::command_substitution_open, stt::executable, stt::field,
                stt::command_substitution_close, stt::arithmetic_expansion_close,
                stt::double_quoted_string_close}},
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

// TODO a single quoted string can be considered an executable
TEST(TestShellTokenizer, SingleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(echo 'stuff')", {stt::executable, stt::single_quoted_string}},
        {R"(echo 'var=2')", {stt::executable, stt::single_quoted_string}},
        {R"(echo 'literal $0')", {stt::executable, stt::single_quoted_string}},
        // Executable
        {R"('stuff')", {stt::executable}},
        {R"('var=2')", {stt::executable}},
        {R"('literal $0')", {stt::executable}},
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
            {stt::executable, stt::double_quoted_string_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "l$(ls -l)")!",
            {stt::executable, stt::double_quoted_string_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "$(ls -l) literal")!",
            {stt::executable, stt::double_quoted_string_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "$(ls -l)l")!",
            {stt::executable, stt::double_quoted_string_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "literal $(ls -l) literal")!",
            {stt::executable, stt::double_quoted_string_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "l$(ls -l)l")!",
            {stt::executable, stt::double_quoted_string_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close,
                stt::double_quoted_string_close}},
        {R"!("$(something)" something)!",
            {stt::double_quoted_string_open, stt::command_substitution_open, stt::executable,
                stt::command_substitution_close, stt::double_quoted_string_close, stt::field}},
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
            {stt::executable, stt::double_quoted_string_open, stt::backtick_substitution_open,
                stt::executable, stt::field, stt::backtick_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "l`ls -l`")!",
            {stt::executable, stt::double_quoted_string_open, stt::backtick_substitution_open,
                stt::executable, stt::field, stt::backtick_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "`ls -l` literal")!",
            {stt::executable, stt::double_quoted_string_open, stt::backtick_substitution_open,
                stt::executable, stt::field, stt::backtick_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "`ls -l`l")!",
            {stt::executable, stt::double_quoted_string_open, stt::backtick_substitution_open,
                stt::executable, stt::field, stt::backtick_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "literal `ls -l` literal")!",
            {stt::executable, stt::double_quoted_string_open, stt::backtick_substitution_open,
                stt::executable, stt::field, stt::backtick_substitution_close,
                stt::double_quoted_string_close}},
        {R"!(ls "l`ls -l`l")!",
            {stt::executable, stt::double_quoted_string_open, stt::backtick_substitution_open,
                stt::executable, stt::field, stt::backtick_substitution_close,
                stt::double_quoted_string_close}},
        {R"!("`something`" something)!",
            {stt::double_quoted_string_open, stt::backtick_substitution_open, stt::executable,
                stt::backtick_substitution_close, stt::double_quoted_string_close, stt::field}},
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
        {"echo 291292;", {stt::executable, stt::field, stt::control}},
        {"echo 291292", {stt::executable, stt::field}},
        {"echo 2111111a9sd1c2d92", {stt::executable, stt::field}},
        {"test echo", {stt::executable, stt::field}},
        {"ls &", {stt::executable, stt::control}},
        {"ls & ls -l", {stt::executable, stt::control, stt::executable, stt::field}},
        {"{ echo; }", {stt::compound_command_open, stt::executable, stt::control,
                          stt::compound_command_close}},
        {"(ls -l)", {stt::subshell_open, stt::executable, stt::field, stt::subshell_close}},
        {"$(ls -l)", {stt::command_substitution_open, stt::executable, stt::field,
                         stt::command_substitution_close}},
        {"diff <(ls -l)", {stt::executable, stt::process_substitution_open, stt::executable,
                              stt::field, stt::process_substitution_close}},
        {"diff >(ls -l)", {stt::executable, stt::process_substitution_open, stt::executable,
                              stt::field, stt::process_substitution_close}},
        {"var= echo hello", {stt::variable_definition, stt::equal, stt::executable, stt::field}},
        {"var=$[1+$(echo ]2)]",
            {stt::variable_definition, stt::equal, stt::arithmetic_expansion_open,
                stt::command_substitution_open, stt::executable, stt::field,
                stt::command_substitution_close, stt::arithmetic_expansion_close}},
        {"var=$[1+`echo 2`]",
            {stt::variable_definition, stt::equal, stt::arithmetic_expansion_open,
                stt::backtick_substitution_open, stt::executable, stt::field,
                stt::backtick_substitution_close, stt::arithmetic_expansion_close}},
        {"(( 1 + `echo 2` ))",
            {stt::arithmetic_expansion_open, stt::backtick_substitution_open, stt::executable,
                stt::field, stt::backtick_substitution_close, stt::arithmetic_expansion_close}},
        {"var=($(echo 1))",
            {stt::variable_definition, stt::equal, stt::array_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close, stt::array_close}},
        {"var=($(echo 1) `echo 2`)",
            {stt::variable_definition, stt::equal, stt::array_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close,
                stt::backtick_substitution_open, stt::executable, stt::field,
                stt::backtick_substitution_close, stt::array_close}},
        {"var=($(echo 1) `echo 2`) ls -l",
            {stt::variable_definition, stt::equal, stt::array_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close,
                stt::backtick_substitution_open, stt::executable, stt::field,
                stt::backtick_substitution_close, stt::array_close, stt::executable, stt::field}},
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
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"ls | cat", {stt::executable, stt::control, stt::executable}},
        {"ls & ls | cat",
            {stt::executable, stt::control, stt::executable, stt::control, stt::executable}},
        {"ls -l | cat", {stt::executable, stt::field, stt::control, stt::executable}},
        {"ls -l | cat | grep passwd", {stt::executable, stt::field, stt::control, stt::executable,
                                          stt::control, stt::executable, stt::field}},
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

TEST(TestShellTokenizer, CommandSequence)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"ls ; cat", {stt::executable, stt::control, stt::executable}},
        {"ls -l ; cat", {stt::executable, stt::field, stt::control, stt::executable}},
        {"ls -l ; cat ; grep passwd", {stt::executable, stt::field, stt::control, stt::executable,
                                          stt::control, stt::executable, stt::field}},
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

TEST(TestShellTokenizer, RedirectionTokens)
{
    std::vector<std::string> samples{"&>>", "1>", ">", ">>", ">|", ">&", "1>&", "1>&2", "1>&2-",
        "1>&-", "<", "1<", "2<&", "2<<", "2<<-", "<<-", "<<", "<<<", "1<<<", "1<&", "1<", "<&",
        "1<>", "<>", "11>", "21>&", "11>&22", "21>&12-", "111>&-", "221<", "332<&", "12<<", "42<<-",
        "22<<<", "11<&", "31<", "221<>"};

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
        {"ls args <&221 file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args <&221", {stt::executable, stt::field, stt::redirection}},
        {"ls args 01> file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 02>> file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 03< file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 04<< file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 05<& file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 06<&- file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 01<&21 file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 01<&21", {stt::executable, stt::field, stt::redirection}},
        {"ls args 01>& file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 01>&31 file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 01>&31", {stt::executable, stt::field, stt::redirection}},
        {"ls args 01>&- file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 10<<- file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 22<> file", {stt::executable, stt::field, stt::redirection, stt::field}},
        {"ls args 33>| file", {stt::executable, stt::field, stt::redirection, stt::field}},
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
        {"var=$(( 1+1 ))", {stt::variable_definition, stt::equal, stt::arithmetic_expansion}},
        {"var=$[ 1+1 ]", {stt::variable_definition, stt::equal, stt::arithmetic_expansion}},
        {"var=$[1+1]", {stt::variable_definition, stt::equal, stt::arithmetic_expansion}},
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
        {"echo ${var[$(echo @)]}",
            {stt::executable, stt::parameter_expansion_open, stt::command_substitution_open,
                stt::executable, stt::field, stt::command_substitution_close,
                stt::parameter_expansion_close}},
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
            {stt::executable, stt::control, stt::executable, stt::double_quoted_string,
                stt::control, stt::executable, stt::field, stt::single_quoted_string, stt::control,
                stt::executable, stt::field, stt::field}},
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
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"(( var=1+1 ))", {stt::arithmetic_expansion}},
        {"(( var=$(echo 1) ))",
            {stt::arithmetic_expansion_open, stt::command_substitution_open, stt::executable,
                stt::field, stt::command_substitution_close, stt::arithmetic_expansion_close}},
        {"(( var=`echo 1` ))",
            {stt::arithmetic_expansion_open, stt::backtick_substitution_open, stt::executable,
                stt::field, stt::backtick_substitution_close, stt::arithmetic_expansion_close}},
        {"command (( var=`echo 1` )) -2 -3",
            {stt::executable, stt::arithmetic_expansion_open, stt::backtick_substitution_open,
                stt::executable, stt::field, stt::backtick_substitution_close,
                stt::arithmetic_expansion_close, stt::field, stt::field}},
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

TEST(TestShellTokenizer, Negation)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"! ls", {stt::control, stt::executable}}};

    for (const auto &[input, expected_tokens] : samples) {
        shell_tokenizer tokenizer(input);

        auto tokens = tokenizer.tokenize();
        ASSERT_EQ(tokens.size(), expected_tokens.size()) << input;

        for (std::size_t i = 0; i < tokens.size(); ++i) {
            EXPECT_EQ(tokens[i].type, expected_tokens[i]) << input;
        }
    }
}

TEST(TestShellTokenizer, CompoundCommands)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"{ echo; }", {stt::compound_command_open, stt::executable, stt::control,
                          stt::compound_command_close}},
        {"{ ls -l ; echo hello; }",
            {stt::compound_command_open, stt::executable, stt::field, stt::control, stt::executable,
                stt::field, stt::control, stt::compound_command_close}},
        {"{ ls -l | grep passwd; }",
            {stt::compound_command_open, stt::executable, stt::field, stt::control, stt::executable,
                stt::field, stt::control, stt::compound_command_close}},
        {R"({ "command"; })", {stt::compound_command_open, stt::executable, stt::control,
                                  stt::compound_command_close}},
        {R"({ 'command'; })", {stt::compound_command_open, stt::executable, stt::control,
                                  stt::compound_command_close}},
        {R"({ "ls" -l; })", {stt::compound_command_open, stt::executable, stt::field, stt::control,
                                stt::compound_command_close}},
        {R"({ 'ls' -l; })", {stt::compound_command_open, stt::executable, stt::field, stt::control,
                                stt::compound_command_close}},
        {R"({ var=10 ls -l; })",
            {stt::compound_command_open, stt::variable_definition, stt::equal, stt::field,
                stt::executable, stt::field, stt::control, stt::compound_command_close}},
        {R"({ var= ls -l; })",
            {stt::compound_command_open, stt::variable_definition, stt::equal, stt::executable,
                stt::field, stt::control, stt::compound_command_close}},
        {R"!({ "$(echo ls)" -l; })!",
            {stt::compound_command_open, stt::double_quoted_string_open,
                stt::command_substitution_open, stt::executable, stt::field,
                stt::command_substitution_close, stt::double_quoted_string_close, stt::field,
                stt::control, stt::compound_command_close}},
        {R"!({ echo }; })!", {stt::compound_command_open, stt::executable, stt::curly_brace_close,
                                 stt::control, stt::compound_command_close}},
        {R"!({ echo {}; })!",
            {stt::compound_command_open, stt::executable, stt::curly_brace_open,
                stt::curly_brace_close, stt::control, stt::compound_command_close}},
        {R"!({ echo {};})!",
            {stt::compound_command_open, stt::executable, stt::curly_brace_open,
                stt::curly_brace_close, stt::control, stt::compound_command_close}},
        {R"!({ echo { }; })!",
            {stt::compound_command_open, stt::executable, stt::curly_brace_open,
                stt::curly_brace_close, stt::control, stt::compound_command_close}},
        {R"!(echo { }; { echo; })!",
            {stt::executable, stt::curly_brace_open, stt::curly_brace_close, stt::control,
                stt::compound_command_open, stt::executable, stt::control,
                stt::compound_command_close}},
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

TEST(TestShellTokenizer, Subshell)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"( echo )", {stt::subshell_open, stt::executable, stt::subshell_close}},
        {"ls | ( echo )", {stt::executable, stt::control, stt::subshell_open, stt::executable,
                              stt::subshell_close}},
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

TEST(TestShellTokenizer, FileRedirection)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {"$(<file)", {stt::redirection}},
        {"$(< $( echo ))",
            {stt::file_redirection_open, stt::command_substitution_open, stt::executable,
                stt::command_substitution_close, stt::file_redirection_close}},
        {"echo $(< $( echo ))",
            {stt::executable, stt::file_redirection_open, stt::command_substitution_open,
                stt::executable, stt::command_substitution_close, stt::file_redirection_close}},
        {"echo $(<file)", {stt::executable, stt::redirection}},
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
