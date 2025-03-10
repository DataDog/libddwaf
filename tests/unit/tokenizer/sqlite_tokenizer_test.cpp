// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "tokenizer/sqlite.hpp"

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

TEST(TestSqliteTokenizer, Commands)
{
    std::vector<std::string> samples{"SELECT", "DISTINCT", "ALL", "FROM", "WHERE", "GROUP",
        "HAVING", "WINDOW", "VALUES", "OFFSET", "LIMIT", "ORDER", "BY", "ASC", "DESC", "UNION",
        "INTERSECT", "EXCEPT", "NULL", "AS"};

    for (const auto &statement : samples) {
        {
            sqlite_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::keyword);
        }

        {
            auto lc_statement = str_to_lower(statement);
            sqlite_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::keyword);
        }
    }
}

TEST(TestSqliteTokenizer, Identifiers)
{
    std::vector<std::string> samples{"random", "WoRd", "$22", "a231a234", "asb123$21321", "Ω_a091",
        "ran$om", "WoR$d", "a231a234$", "asb12321321", "_a091_", "a23__$__12"};

    for (const auto &statement : samples) {
        sqlite_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::identifier) << statement;
        EXPECT_TRUE(obtained_tokens[0].str == statement) << statement;
    }
}

TEST(TestSqliteTokenizer, Number)
{
    std::vector<std::string> samples{"0", "1.1", "1", "1", "1e17", "1.0101e+17", "0x22", "0xFF",
        "0122", "00", "0b101", "0B11_00", "0b110_0", "0X12_3", "0xFA_AA", "0o77", "0O7_7",
        "012_345", "0.000_00", "-1.2", "-0.1", "-1", "+1", "+1.2", "+0.1"};

    for (const auto &statement : samples) {
        sqlite_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::number);
    }
}

TEST(TestSqliteTokenizer, BinaryOperators)
{
    // Asterisk is a special case
    std::vector<std::string> samples{"+", "-", "/", "%", "=", "!=", "<>", "<", ">",
        ">=", "<=", "<<", ">>", "||", "OR", "AND", "IN", "BETWEEN", "LIKE", "GLOB", "ESCAPE",
        "COLLATE", "REGEXP", "MATCH", "NOTNULL", "ISNULL", "NOT", "IS"};

    for (const auto &statement : samples) {
        {
            sqlite_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::binary_operator) << statement;
        }

        {
            auto lc_statement = str_to_lower(statement);
            sqlite_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << lc_statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::binary_operator) << lc_statement;
        }
    }
}

TEST(TestSqliteTokenizer, BitwiseOperators)
{
    std::vector<std::string> samples{"&", "|", "~"};

    for (const auto &statement : samples) {
        sqlite_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::bitwise_operator);
        EXPECT_TRUE(obtained_tokens[0].str == statement);
    }
}

TEST(TestSqliteTokenizer, Expression)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(1+1)", {stt::number, stt::binary_operator, stt::number}},
        {R"(+1+1)", {stt::number, stt::binary_operator, stt::number}},
        {R"(+1+1)", {stt::number, stt::binary_operator, stt::number}},
        {R"(-1+1)", {stt::number, stt::binary_operator, stt::number}},
        {R"(1-1)", {stt::number, stt::binary_operator, stt::number}},
        {R"(-1-1)", {stt::number, stt::binary_operator, stt::number}},
        {R"(+1-1)", {stt::number, stt::binary_operator, stt::number}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        sqlite_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        // ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqliteTokenizer, InlineComment)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(/* inline comment */)", {stt::inline_comment}},
        {R"(SELECT /* inline comment */)", {stt::keyword, stt::inline_comment}},
        {R"(/* inline comment */ SELECT)", {stt::inline_comment, stt::keyword}},
        {R"(/* multiline 
               inline comment */)",
            {stt::inline_comment}},
        {R"(/* missing end)", {stt::inline_comment}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        sqlite_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqliteTokenizer, EolComment)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(-- eol comment)", {stt::eol_comment}},
        {R"(hello -- eol comment)", {stt::identifier, stt::eol_comment}},
        {R"(-- eol comment SELECT)", {stt::eol_comment}},
        {R"(-- multiline eol comment
        SELECT)",
            {stt::eol_comment, stt::keyword}},

    };

    for (const auto &[statement, expected_tokens] : samples) {
        sqlite_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqliteTokenizer, DoubleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"("this is a string")", {stt::identifier}},
        {R"("this is ""quoted"" string")", {stt::identifier}},
        {R"("this is """"quoted"""" string")", {stt::identifier}},
        {R"("this \n is """"""quoted"""""" string")", {stt::identifier}},
        {R"("this is ""quoted"" string" and "another string")",
            {stt::identifier, stt::binary_operator, stt::identifier}},
        {R"("this is an unterminated string)", {stt::identifier}},
        {R"(SELECT "colname")", {stt::keyword, stt::identifier}},
        {R"("colname" FROM)", {stt::identifier, stt::keyword}},
        {R"(SELECT "colname" FROM "table";)",
            {stt::keyword, stt::identifier, stt::keyword, stt::identifier, stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        sqlite_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqliteTokenizer, SingleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"('this is a string')", {stt::single_quoted_string}},
        {R"('this is ''quoted'' string')", {stt::single_quoted_string}},
        {R"('this is ''''''quoted'' string')", {stt::single_quoted_string}},
        {R"('this \n is ''''''quoted'''''' string')", {stt::single_quoted_string}},
        {R"('this is ''quoted'' string' and 'another string')",
            {stt::single_quoted_string, stt::binary_operator, stt::single_quoted_string}},
        {R"('this is an unterminated string)", {stt::single_quoted_string}},
        {R"(SELECT 'colname')", {stt::keyword, stt::single_quoted_string}},
        {R"('colname' FROM)", {stt::single_quoted_string, stt::keyword}},
        {R"(SELECT 'colname' FROM 'table';)",
            {stt::keyword, stt::single_quoted_string, stt::keyword, stt::single_quoted_string,
                stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        sqlite_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqliteTokenizer, BacktickQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(`this is a string`)", {stt::identifier}},
        {R"(`this is ``quoted`` string`)", {stt::identifier}},
        {R"(`this is ``````quoted`` string`)", {stt::identifier}},
        {R"(`this \n is ``````quoted`````` string`)", {stt::identifier}},
        {R"(`this is ``quoted`` string` and `another string`)",
            {stt::identifier, stt::binary_operator, stt::identifier}},
        {R"(`this is an unterminated string)", {stt::identifier}},
        {R"(SELECT `colname`)", {stt::keyword, stt::identifier}},
        {R"(`colname` FROM)", {stt::identifier, stt::keyword}},
        {R"(SELECT `colname` FROM `table`;)",
            {stt::keyword, stt::identifier, stt::keyword, stt::identifier, stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        sqlite_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestSqliteTokenizer, Basic)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(SELECT x FROM t WHERE id='admin'--)",
            {stt::keyword, stt::identifier, stt::keyword, stt::identifier, stt::keyword,
                stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::eol_comment}},
        {R"(SELECT * FROM TEST;)",
            {stt::keyword, stt::asterisk, stt::keyword, stt::identifier, stt::query_end}},
        {R"(SELECT a.* FROM TEST;)", {stt::keyword, stt::identifier, stt::dot, stt::asterisk,
                                         stt::keyword, stt::identifier, stt::query_end}},
        {R"(SELECT DISTINCT NAME FROM TEST;)", {stt::keyword, stt::keyword, stt::identifier,
                                                   stt::keyword, stt::identifier, stt::query_end}},
        {R"(SELECT ID, COUNT(1) FROM TEST GROUP BY ID;)",
            {stt::keyword, stt::identifier, stt::comma, stt::identifier, stt::parenthesis_open,
                stt::number, stt::parenthesis_close, stt::keyword, stt::identifier, stt::keyword,
                stt::keyword, stt::identifier, stt::query_end}},
        {R"(SELECT NAME, SUM(VAL) FROM TEST GROUP BY NAME HAVING COUNT(1) > 2;)",
            {stt::keyword, stt::identifier, stt::comma, stt::identifier, stt::parenthesis_open,
                stt::identifier, stt::parenthesis_close, stt::keyword, stt::identifier,
                stt::keyword, stt::keyword, stt::identifier, stt::keyword, stt::identifier,
                stt::parenthesis_open, stt::number, stt::parenthesis_close, stt::binary_operator,
                stt::number, stt::query_end}},
        {R"(SELECT 'ID' COL, MAX(ID) AS MAX FROM TEST;)",
            {stt::keyword, stt::single_quoted_string, stt::identifier, stt::comma, stt::identifier,
                stt::parenthesis_open, stt::identifier, stt::parenthesis_close, stt::keyword,
                stt::identifier, stt::keyword, stt::identifier, stt::query_end}},
        {R"(SELECT * FROM TEST LIMIT 1000;)",
            {stt::keyword, stt::asterisk, stt::keyword, stt::identifier, stt::keyword, stt::number,
                stt::query_end}},
        {R"(SELECT * FROM table WHERE title LIKE '%' || ? || '%';)",
            {stt::keyword, stt::asterisk, stt::keyword, stt::identifier, stt::keyword,
                stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::binary_operator, stt::questionmark, stt::binary_operator,
                stt::single_quoted_string, stt::query_end}},

        {R"(SELECT name FROM (SELECT * FROM sqlite_master UNION ALL SELECT * FROM sqlite_temp_master) WHERE type='table' ORDER BY name)",
            {stt::keyword, stt::identifier, stt::keyword, stt::parenthesis_open, stt::keyword,
                stt::asterisk, stt::keyword, stt::identifier, stt::keyword, stt::keyword,
                stt::keyword, stt::asterisk, stt::keyword, stt::identifier, stt::parenthesis_close,
                stt::keyword, stt::identifier, stt::binary_operator, stt::single_quoted_string,
                stt::keyword, stt::keyword, stt::identifier}},

        {R"(SELECT x FROM t1 WHERE 'abc' = b ORDER BY x;)",
            {stt::keyword, stt::identifier, stt::keyword, stt::identifier, stt::keyword,
                stt::single_quoted_string, stt::binary_operator, stt::identifier, stt::keyword,
                stt::keyword, stt::identifier, stt::query_end}},

        {R"(SELECT x FROM t1 ORDER BY (c||''), x;)",
            {stt::keyword, stt::identifier, stt::keyword, stt::identifier, stt::keyword,
                stt::keyword, stt::parenthesis_open, stt::identifier, stt::binary_operator,
                stt::single_quoted_string, stt::parenthesis_close, stt::comma, stt::identifier,
                stt::query_end}},

        {R"(SELECT 3 < 4, 3 <> 5, 4 >= 4, 5 != 5;)",
            {stt::keyword, stt::number, stt::binary_operator, stt::number, stt::comma, stt::number,
                stt::binary_operator, stt::number, stt::comma, stt::number, stt::binary_operator,
                stt::number, stt::comma, stt::number, stt::binary_operator, stt::number,
                stt::query_end}},

        {R"(SELECT 'wolf' || 'hound';)",
            {stt::keyword, stt::single_quoted_string, stt::binary_operator,
                stt::single_quoted_string, stt::query_end}},

        {R"(SELECT * FROM foo WHERE bar = '" test "';)",
            {stt::keyword, stt::asterisk, stt::keyword, stt::identifier, stt::keyword,
                stt::identifier, stt::binary_operator, stt::single_quoted_string, stt::query_end}},

        // https://www.sqlite.org/faq.html (14)
        {R"(SELECT  1 FROM u WHERE mail = 'vega@example.com\\''' LIMIT 1 ;)",
            {stt::keyword, stt::number, stt::keyword, stt::identifier, stt::keyword,
                stt::identifier, stt::binary_operator, stt::single_quoted_string, stt::keyword,
                stt::number, stt::query_end}},

        {R"(SELECT /*! simple inline comment */ * FROM dual)",
            {stt::keyword, stt::inline_comment, stt::asterisk, stt::keyword, stt::identifier}},

        {R"(SELECT -- /*! simple inline comment */ * FROM dual)", {stt::keyword, stt::eol_comment}},

        {R"(label: SELECT * FROM productLine WHERE model = 'MacPro 2013' /*randomgarbage')",
            {stt::identifier, stt::colon, stt::keyword, stt::asterisk, stt::keyword,
                stt::identifier, stt::keyword, stt::identifier, stt::binary_operator,
                stt::single_quoted_string, stt::inline_comment}}};

    for (const auto &[statement, expected_tokens] : samples) {
        sqlite_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type) << statement;
        }
    }
}

} // namespace
