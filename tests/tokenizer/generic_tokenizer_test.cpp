// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test_utils.hpp"
#include "tokenizer/generic_sql.hpp"

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

TEST(TestgenericTokenizer, Commands)
{
    std::vector<std::string> samples{
        "SELECT", "FROM", "WHERE", "GROUP BY", "OFFSET", "LIMIT", "ORDER BY", "ASC", "DESC"};

    for (const auto &statement : samples) {
        {
            generic_sql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::command) << statement;
        }

        {
            auto lc_statement = str_to_lower(statement);
            generic_sql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::command);
        }
    }
}

TEST(TestgenericTokenizer, Identifiers)
{
    std::vector<std::string> samples{"random", "WoRd", "a231a234", "asb123$21321", "Ω_a091",
        "ran$om", "WoR$d", "a231a234$", "asb12321321", "_a091_", "a23__$__12"};

    for (const auto &statement : samples) {
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::identifier) << statement;
        EXPECT_TRUE(obtained_tokens[0].str == statement) << statement;
    }
}

TEST(TestgenericTokenizer, Number)
{
    std::vector<std::string> samples{
        "0", "1.1", "+1", "-1", "1e17", "-1.0101e+17", "0x22", "0xFF", "0122", "00"};

    for (const auto &statement : samples) {
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::number);
    }
}

TEST(TestgenericTokenizer, BinaryOperators)
{
    // Asterisk is a special case
    std::vector<std::string> samples{"+", "-", "/", "%", "=", "!=", "<>", "<", ">",
        ">=", "<=", "||", "ALL", "OR", "AND", "ANY", "BETWEEN", "LIKE", "IN", "MOD", "IS NULL",
        "IS NOT NULL", "NOT"};

    for (const auto &statement : samples) {
        {
            generic_sql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::binary_operator);
        }

        {
            auto lc_statement = str_to_lower(statement);
            generic_sql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::binary_operator);
        }
    }
}

TEST(TestgenericTokenizer, BitwiseOperators)
{
    std::vector<std::string> samples{"&", "|", "~"};

    for (const auto &statement : samples) {
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::bitwise_operator);
        EXPECT_TRUE(obtained_tokens[0].str == statement);
    }
}

TEST(TestgenericTokenizer, InlineComment)
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
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestgenericTokenizer, EolComment)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(-- eol comment)", {stt::eol_comment}},
        {R"(hello -- eol comment)", {stt::identifier, stt::eol_comment}},
        {R"(-- eol comment SELECT)", {stt::eol_comment}},
        {R"(-- multiline eol comment
        SELECT)",
            {stt::eol_comment, stt::command}},

    };

    for (const auto &[statement, expected_tokens] : samples) {
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestgenericTokenizer, DoubleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"("this is a string")", {stt::double_quoted_string}},
        {R"("this is \"quoted\" string")", {stt::double_quoted_string}},
        {R"("this is \\\\\"quoted\" string")", {stt::double_quoted_string}},
        {R"("this \n is \\\\\"quoted\\\\\" string")", {stt::double_quoted_string}},
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
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestgenericTokenizer, SingleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"('this is a string')", {stt::single_quoted_string}},
        {R"('this is \'quoted\' string')", {stt::single_quoted_string}},
        {R"('this is \\\\\'quoted\' string')", {stt::single_quoted_string}},
        {R"('this \n is \\\\\'quoted\\\\\' string')", {stt::single_quoted_string}},
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
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestgenericTokenizer, BacktickQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(`this is a string`)", {stt::back_quoted_string}},
        {R"(`this is \`quoted\` string`)", {stt::back_quoted_string}},
        {R"(`this is \\\\\`quoted\` string`)", {stt::back_quoted_string}},
        {R"(`this \n is \\\\\`quoted\\\\\` string`)", {stt::back_quoted_string}},
        {R"(`this is \`quoted\` string` and `another string`)",
            {stt::back_quoted_string, stt::binary_operator, stt::back_quoted_string}},
        {R"(`this is an unterminated string)", {stt::back_quoted_string}},
        {R"(SELECT `colname`)", {stt::command, stt::back_quoted_string}},
        {R"(`colname` FROM)", {stt::back_quoted_string, stt::command}},
        {R"(SELECT `colname` FROM `table`;)", {stt::command, stt::back_quoted_string, stt::command,
                                                  stt::back_quoted_string, stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestgenericTokenizer, Basic)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(SELECT x FROM t WHERE id='admin'--)",
            {stt::command, stt::identifier, stt::command, stt::identifier, stt::command,
                stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::eol_comment}},
        {R"(SELECT * FROM TEST;)",
            {stt::command, stt::asterisk, stt::command, stt::identifier, stt::query_end}},
        {R"(SELECT a.* FROM TEST;)", {stt::command, stt::identifier, stt::dot, stt::asterisk,
                                         stt::command, stt::identifier, stt::query_end}},
        {R"(SELECT DISTINCT NAME FROM TEST;)", {stt::command, stt::command, stt::identifier,
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
                stt::parenthesis_open, stt::identifier, stt::parenthesis_close, stt::command,
                stt::identifier, stt::command, stt::identifier, stt::query_end}},
        {R"(SELECT * FROM TEST LIMIT 1000;)",
            {stt::command, stt::asterisk, stt::command, stt::identifier, stt::command, stt::number,
                stt::query_end}},
        {R"(SELECT * FROM table WHERE title LIKE '%' || ? || '%';)",
            {stt::command, stt::asterisk, stt::command, stt::identifier, stt::command,
                stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::binary_operator, stt::questionmark, stt::binary_operator,
                stt::single_quoted_string, stt::query_end}},

        {R"(SELECT name FROM (SELECT * FROM generic_master UNION ALL SELECT * FROM generic_temp_master) WHERE type='table' ORDER BY name)",
            {stt::command, stt::identifier, stt::command, stt::parenthesis_open, stt::command,
                stt::asterisk, stt::command, stt::identifier, stt::command, stt::command,
                stt::asterisk, stt::command, stt::identifier, stt::parenthesis_close, stt::command,
                stt::identifier, stt::binary_operator, stt::single_quoted_string, stt::command,
                stt::identifier}},

        {R"(SELECT x FROM t1 WHERE 'abc' = b ORDER BY x;)",
            {stt::command, stt::identifier, stt::command, stt::identifier, stt::command,
                stt::single_quoted_string, stt::binary_operator, stt::identifier, stt::command,
                stt::identifier, stt::query_end}},

        {R"(SELECT x FROM t1 ORDER BY (c||''), x;)",
            {stt::command, stt::identifier, stt::command, stt::identifier, stt::command,
                stt::parenthesis_open, stt::identifier, stt::binary_operator,
                stt::single_quoted_string, stt::parenthesis_close, stt::comma, stt::identifier,
                stt::query_end}},

        {R"(SELECT 3 < 4, 3 <> 5, 4 >= 4, 5 != 5;)",
            {stt::command, stt::number, stt::binary_operator, stt::number, stt::comma, stt::number,
                stt::binary_operator, stt::number, stt::comma, stt::number, stt::binary_operator,
                stt::number, stt::comma, stt::number, stt::binary_operator, stt::number,
                stt::query_end}},

        {R"(SELECT 'wolf' || 'hound';)",
            {stt::command, stt::single_quoted_string, stt::binary_operator,
                stt::single_quoted_string, stt::query_end}},

        {R"(SELECT * FROM foo WHERE bar = '" test "';)",
            {stt::command, stt::asterisk, stt::command, stt::identifier, stt::command,
                stt::identifier, stt::binary_operator, stt::single_quoted_string, stt::query_end}},

        // https://www.generic.org/faq.html (14)
        {R"(SELECT  1 FROM u WHERE mail = 'vega@example.com\\''' LIMIT 1 ;)",
            {stt::command, stt::number, stt::command, stt::identifier, stt::command,
                stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::single_quoted_string, stt::command, stt::number, stt::query_end}},

        {R"(SELECT * FROM productLine WHERE model = 'MacPro 2013' /*randomgarbage')",
            {stt::command, stt::asterisk, stt::command, stt::identifier, stt::command,
                stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::inline_comment}}};

    for (const auto &[statement, expected_tokens] : samples) {
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type) << statement;
        }
    }
}

} // namespace
