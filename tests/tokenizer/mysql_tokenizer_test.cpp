// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test_utils.hpp"
#include "tokenizer/mysql.hpp"

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

TEST(TestMySqlTokenizer, UserVariable)
{
    std::vector<std::string> samples{
        "@variable", "@var.var", "@a123a_$as", "@@system_var", "@@v12a1$_", R"(@'da1A\'DDver')"};

    for (const auto &statement : samples) {
        {
            mysql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::identifier);
        }

        {
            auto lc_statement = str_to_lower(statement);
            mysql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::identifier);
        }
    }
}

TEST(TestMySqlTokenizer, Commands)
{
    std::vector<std::string> samples{"SELECT", "ALL", "DISTINCT", "DISTINCTROW", "HIGH_PRIORITY",
        "STRAIGHT_JOIN", "SQL_SMALL_RESULT", "SQL_BIG_RESULT", "SQL_BUFFER_RESULT", "SQL_NO_CACHE",
        "SQL_CALC_FOUND_ROWS", "FROM", "PARTITION", "WHERE", "GROUP BY", "WITH ROLLUP", "HAVING",
        "WINDOW", "ORDER BY", "ASC", "DESC", "LIMIT", "OFFSET", "AS"};

    for (const auto &statement : samples) {
        {
            mysql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::command);
        }

        {
            auto lc_statement = str_to_lower(statement);
            mysql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::command);
        }
    }
}

TEST(TestMySqlTokenizer, Identifiers)
{
    std::vector<std::string> samples{
        "random", "WoRd", "a231a234", "asb123$21321", "\u0081_a091", "12a2312"};

    for (const auto &statement : samples) {
        mysql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::identifier) << statement;
        EXPECT_TRUE(obtained_tokens[0].str == statement) << statement;
    }
}

TEST(TestMySqlTokenizer, Number)
{
    std::vector<std::string> samples{
        "0", "1.1", "+1", "-1", "1e17", "-1.0101e+17", "0x22", "0xFF", "0122", "00"};

    for (const auto &statement : samples) {
        mysql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::number);
    }
}

TEST(TestMySqlTokenizer, BinaryOperators)
{
    // Asterisk is a special case
    std::vector<std::string> samples{">", ">=", "<", "<>", "!=", "<=", "<=>", "%", "+", "-", "/",
        ":=", "=", "&&", "!", "||", "MOD", "AND", "BETWEEN", "BINARY", "CASE", "DIV", "IS NULL",
        "IS NOT NULL", "IS NOT", "IS", "LAST_DAY", "NOT BETWEEN", "NOT LIKE", "NOT REGEXP", "NOT",
        "REGEXP", "XOR", "OR", "RLIKE", "SOUNDS LIKE", "LIKE"};

    for (const auto &statement : samples) {
        {
            mysql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::binary_operator);
        }

        {
            auto lc_statement = str_to_lower(statement);
            mysql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::binary_operator);
        }
    }
}

TEST(TestMySqlTokenizer, BitwiseOperators)
{
    std::vector<std::string> samples{"^", "&", "|", "~", ">>", "<<"};

    for (const auto &statement : samples) {
        mysql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::bitwise_operator);
        EXPECT_TRUE(obtained_tokens[0].str == statement);
    }
}

TEST(TestMySqlTokenizer, InlineComment)
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
        mysql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestMySqlTokenizer, EolComment)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(-- eol comment)", {stt::eol_comment}},
        {R"(hello -- eol comment)", {stt::identifier, stt::eol_comment}},
        {R"(-- eol comment SELECT)", {stt::eol_comment}},
        {R"(-- multiline eol comment
        SELECT)",
            {stt::eol_comment, stt::command}},
        {R"(# eol comment)", {stt::eol_comment}},
        {R"(hello#- eol comment)", {stt::identifier, stt::eol_comment}},
        {R"(# eol comment SELECT)", {stt::eol_comment}},
        {R"(# multiline eol comment
        SELECT)",
            {stt::eol_comment, stt::command}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        mysql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestMySqlTokenizer, DoubleQuotedString)
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
        mysql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestMySqlTokenizer, SingleQuotedString)
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
        mysql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestMySqlTokenizer, BacktickQuotedString)
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
        mysql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestMySqlTokenizer, Basic)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(SELECT x FROM t WHERE id='admin'--)",
            {stt::command, stt::identifier, stt::command, stt::identifier, stt::command,
                stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::eol_comment}},
        {R"(SELECT x FROM t WHERE id='admin'#whatever)",
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

        {R"(SELECT name FROM (SELECT * FROM sqlite_master UNION ALL SELECT * FROM sqlite_temp_master) WHERE type='table' ORDER BY name)",
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

        // https://www.sqlite.org/faq.html (14)
        {R"(SELECT  1 FROM u WHERE mail = 'vega@example.com\\''' LIMIT 1 ;)",
            {stt::command, stt::number, stt::command, stt::identifier, stt::command,
                stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::single_quoted_string, stt::command, stt::number, stt::query_end}},

        {R"(SELECT /*! simple inline comment */ * FROM dual)",
            {stt::command, stt::inline_comment, stt::asterisk, stt::command, stt::identifier}},

        {R"(SELECT -- /*! simple inline comment */ * FROM dual)", {stt::command, stt::eol_comment}},

        {R"(SELECT * FROM productLine WHERE model = 'MacPro 2013' /*randomgarbage')",
            {stt::command, stt::asterisk, stt::command, stt::identifier, stt::command,
                stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::inline_comment}}};

    for (const auto &[statement, expected_tokens] : samples) {
        mysql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();

        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type) << statement;
        }
    }
}

} // namespace
