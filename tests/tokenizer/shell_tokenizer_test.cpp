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
    shell_tokenizer tokenizer("ls -l");

    auto tokens = tokenizer.tokenize();
    EXPECT_EQ(tokens.size(), 2);
    EXPECT_EQ(tokens[0].type, stt::executable);
    EXPECT_EQ(tokens[1].type, stt::field);
}

TEST(TestShellTokenizer, BasicDoubleQuotedString)
{
    shell_tokenizer tokenizer(R"(ls "string")");

    auto tokens = tokenizer.tokenize();
    EXPECT_EQ(tokens.size(), 4);
    EXPECT_EQ(tokens[0].type, stt::executable);
    EXPECT_EQ(tokens[1].type, stt::double_quote);
    EXPECT_EQ(tokens[2].type, stt::literal);
    EXPECT_EQ(tokens[3].type, stt::double_quote);
}

TEST(TestShellTokenizer, DoubleQuotedStringWithCommandSubstitution)
{
    shell_tokenizer tokenizer("ls \"$(ls -l)\"");

    auto tokens = tokenizer.tokenize();
    EXPECT_EQ(tokens.size(), 7);
    EXPECT_EQ(tokens[0].type, stt::executable);
    EXPECT_EQ(tokens[1].type, stt::double_quote);
    EXPECT_EQ(tokens[2].type, stt::command_substitution_open);
    EXPECT_EQ(tokens[3].type, stt::executable);
    EXPECT_EQ(tokens[4].type, stt::field);
    EXPECT_EQ(tokens[5].type, stt::command_substitution_close);
    EXPECT_EQ(tokens[6].type, stt::double_quote);
}

TEST(TestShellTokenizer, DoubleQuotedStringWithBacktickSubstitution)
{
    shell_tokenizer tokenizer("ls \"`ls -l`\"");

    auto tokens = tokenizer.tokenize();
    EXPECT_EQ(tokens.size(), 7);
    EXPECT_EQ(tokens[0].type, stt::executable);
    EXPECT_EQ(tokens[1].type, stt::double_quote);
    EXPECT_EQ(tokens[2].type, stt::backtick_substitution_open);
    EXPECT_EQ(tokens[3].type, stt::executable);
    EXPECT_EQ(tokens[4].type, stt::field);
    EXPECT_EQ(tokens[5].type, stt::backtick_substitution_close);
    EXPECT_EQ(tokens[6].type, stt::double_quote);
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

TEST(TestShellTokenizer, Redirections)
{
    std::vector<std::string> samples {
        "&>>", "1>", ">", ">>", ">|", ">&", "1>&", "1>&2", "1>&2-", "1>&-", "<", "1<", "2<&", "2<<", "2<<-", "<<-", "<<", "<<<", "1<<<", "1<&", "1<", "<&", "1<>", "<>"
    };

    for (const auto& sample: samples) {
        shell_tokenizer tokenizer(sample);
        auto tokens = tokenizer.tokenize();
        EXPECT_EQ(tokens.size(), 1);
        EXPECT_EQ(tokens[0].type, stt::redirection);
        EXPECT_STRV(tokens[0].str, sample.c_str());
    }
}


} // namespace
