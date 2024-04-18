// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "sql_tokenizer.hpp"
#include "test_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
using stt = sql_token_type;

std::string str_to_lower(const std::string &str)
{
    std::string lower;
    lower.reserve(str.size());
    for (auto c : str) { lower.push_back(ddwaf::tolower(c)); }
    return lower;
}

TEST(TestSqlTokenizer, Commands)
{
    std::vector<std::string> samples{
        "SELECT", "FROM", "WHERE", "GROUP BY", "OFFSET", "LIMIT", "HAVING", "ORDER BY"};

    for (const auto &statement : samples) {
        {
            sql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::command);
        }

        {
            auto lc_statement = str_to_lower(statement);
            sql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::command);
        }
    }
}

TEST(TestSqlTokenizer, Number)
{
    std::vector<std::string> samples{
        "0", "1.1", "+1", "-1", "1e17", "-1.0101e+17", "0x22", "0xFF", "0122", "00"};

    for (const auto &statement : samples) {
        sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::number);
    }
}

TEST(TestSqlTokenizer, BinaryOperators)
{
    // Asterisk is a special case
    std::vector<std::string> samples{"+", "-", "/", "%", "=", "!=", "<>", "<", ">",
        ">=", "<=", "@@", "@>", "<@", "<<", ">>", "||", "NOT", "OR", "XOR", "AND", "IS", "IN",
        "BETWEEN", "LIKE", "REGEXP", "SOUNDS LIKE", "IS NULL", "IS NOT NULL", "DIV", "MOD"};

    for (const auto &statement : samples) {
        {
            sql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::binary_operator);
        }

        {
            auto lc_statement = str_to_lower(statement);
            sql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::binary_operator);
        }
    }
}

TEST(TestSqlTokenizer, BitwiseOperators)
{
    std::vector<std::string> samples{"&", "^", "|", "~"};

    for (const auto &statement : samples) {
        sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::bitwise_operator);
        EXPECT_TRUE(obtained_tokens[0].str == statement);
    }
}

TEST(TestSqlTokenizer, InlineComment)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(/* inline comment */)", {stt::inline_comment}},
        {R"(SELECT /* inline comment */)", {stt::command, stt::inline_comment}},
        {R"(/* inline comment */ SELECT)", {stt::inline_comment, stt::command}},
        {R"(/* multiline 
               inline comment */)",
            {stt::inline_comment}},
        {R"(/* missing end)", {stt::inline_comment}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqlTokenizer, EolComment)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(-- eol comment)", {stt::eol_comment}},
        {R"(# eol comment)", {stt::eol_comment}},
        {R"(hello -- eol comment)", {stt::identifier, stt::eol_comment}},
        {R"(hello # eol comment)", {stt::identifier, stt::eol_comment}},
        {R"(-- eol comment SELECT)", {stt::eol_comment}},
        {R"(# eol comment SELECT)", {stt::eol_comment}},
        {R"(-- multiline eol comment
        SELECT)",
            {stt::eol_comment, stt::command}},
        {R"(# multiline eol comment
        SELECT)",
            {stt::eol_comment, stt::command}},

    };

    for (const auto &[statement, expected_tokens] : samples) {
        sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqlTokenizer, DoubleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"("this is a string")", {stt::double_quoted_string}},
        {R"("this is \"quoted\" string")", {stt::double_quoted_string}},
        {R"("this is \"quoted\" string" and "another string")",
            {stt::double_quoted_string, stt::binary_operator, stt::double_quoted_string}},
        {R"("this is an unterminated string)", {stt::double_quoted_string}},
        {R"(SELECT "colname")", {stt::command, stt::double_quoted_string}},
        {R"("colname" FROM)", {stt::double_quoted_string, stt::command}},
        {R"(SELECT "colname" FROM "table";)",
            {stt::command, stt::double_quoted_string, stt::command, stt::double_quoted_string,
                stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqlTokenizer, SingleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"('this is a string')", {stt::single_quoted_string}},
        {R"('this is \'quoted\' string')", {stt::single_quoted_string}},
        {R"('this is \'quoted\' string' and 'another string')",
            {stt::single_quoted_string, stt::binary_operator, stt::single_quoted_string}},
        {R"('this is an unterminated string)", {stt::single_quoted_string}},
        {R"(SELECT 'colname')", {stt::command, stt::single_quoted_string}},
        {R"('colname' FROM)", {stt::single_quoted_string, stt::command}},
        {R"(SELECT 'colname' FROM 'table';)",
            {stt::command, stt::single_quoted_string, stt::command, stt::single_quoted_string,
                stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqlTokenizer, BacktickQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(`this is a string`)", {stt::back_quoted_string}},
        {R"(`this is \`quoted\` string`)", {stt::back_quoted_string}},
        {R"(`this is \`quoted\` string` and `another string`)",
            {stt::back_quoted_string, stt::binary_operator, stt::back_quoted_string}},
        {R"(`this is an unterminated string)", {stt::back_quoted_string}},
        {R"(SELECT `colname`)", {stt::command, stt::back_quoted_string}},
        {R"(`colname` FROM)", {stt::back_quoted_string, stt::command}},
        {R"(SELECT `colname` FROM `table`;)", {stt::command, stt::back_quoted_string, stt::command,
                                                  stt::back_quoted_string, stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqlTokenizer, Basic)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(SELECT x FROM t WHERE id='admin'#)",
            {stt::command, stt::identifier, stt::command, stt::identifier, stt::command,
                stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::eol_comment}},
        {R"(SELECT * FROM TEST;)",
            {stt::command, stt::asterisk, stt::command, stt::identifier, stt::query_end}},
        {R"(SELECT a.* FROM TEST;)", {stt::command, stt::identifier, stt::dot, stt::asterisk,
                                         stt::command, stt::identifier, stt::query_end}},
        {R"(SELECT DISTINCT NAME FROM TEST;)", {stt::command, stt::identifier, stt::identifier,
                                                   stt::command, stt::identifier, stt::query_end}},
        {R"(SELECT ID, COUNT(1) FROM TEST GROUP BY ID;)",
            {stt::command, stt::identifier, stt::comma, stt::identifier, stt::parenthesis_open,
                stt::number, stt::parenthesis_close, stt::command, stt::identifier, stt::command,
                stt::identifier, stt::query_end}},
        {R"(SELECT NAME, SUM(VAL) FROM TEST GROUP BY NAME HAVING COUNT(1) > 2;)",
            {stt::command, stt::identifier, stt::comma, stt::identifier, stt::parenthesis_open,
                stt::identifier, stt::parenthesis_close, stt::command, stt::identifier,
                stt::command, stt::identifier, stt::command, stt::identifier, stt::parenthesis_open,
                stt::number, stt::parenthesis_close, stt::binary_operator, stt::number,
                stt::query_end}},
        {R"(SELECT 'ID' COL, MAX(ID) AS MAX FROM TEST;)",
            {stt::command, stt::single_quoted_string, stt::identifier, stt::comma, stt::identifier,
                stt::parenthesis_open, stt::identifier, stt::parenthesis_close, stt::identifier,
                stt::identifier, stt::command, stt::identifier, stt::query_end}},
        {R"(SELECT * FROM TEST LIMIT 1000;)",
            {stt::command, stt::asterisk, stt::command, stt::identifier, stt::command, stt::number,
                stt::query_end}}};

    for (const auto &[statement, expected_tokens] : samples) {
        sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

} // namespace