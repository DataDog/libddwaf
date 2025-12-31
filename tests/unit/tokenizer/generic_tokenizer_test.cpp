// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "tokenizer/generic_sql.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
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

TEST(TestGenericTokenizer, DialectFromString)
{
    EXPECT_EQ(sql_dialect_from_type("mysql"), sql_dialect::mysql);
    EXPECT_EQ(sql_dialect_from_type("mysql2"), sql_dialect::mysql);
    EXPECT_EQ(sql_dialect_from_type("MYSQL"), sql_dialect::mysql);
    EXPECT_EQ(sql_dialect_from_type("MYSQL2"), sql_dialect::mysql);

    EXPECT_EQ(sql_dialect_from_type("pgsql"), sql_dialect::pgsql);
    EXPECT_EQ(sql_dialect_from_type("PGSQL"), sql_dialect::pgsql);
    EXPECT_EQ(sql_dialect_from_type("postgresql"), sql_dialect::pgsql);
    EXPECT_EQ(sql_dialect_from_type("POSTGRESQL"), sql_dialect::pgsql);

    EXPECT_EQ(sql_dialect_from_type("sqlite"), sql_dialect::sqlite);
    EXPECT_EQ(sql_dialect_from_type("SQLITE"), sql_dialect::sqlite);

    EXPECT_EQ(sql_dialect_from_type("oracle"), sql_dialect::oracle);
    EXPECT_EQ(sql_dialect_from_type("ORACLE"), sql_dialect::oracle);

    EXPECT_EQ(sql_dialect_from_type("doctrine"), sql_dialect::doctrine);
    EXPECT_EQ(sql_dialect_from_type("DOCTRINE"), sql_dialect::doctrine);

    EXPECT_EQ(sql_dialect_from_type("hsqldb"), sql_dialect::hsqldb);
    EXPECT_EQ(sql_dialect_from_type("HSQLDB"), sql_dialect::hsqldb);

    EXPECT_EQ(sql_dialect_from_type("generic"), sql_dialect::generic);
    EXPECT_EQ(sql_dialect_from_type("GENERIC"), sql_dialect::generic);
    EXPECT_EQ(sql_dialect_from_type("garbage"), sql_dialect::generic);
    EXPECT_EQ(sql_dialect_from_type("unknown"), sql_dialect::generic);
}

TEST(TestGenericTokenizer, DialectToString)
{
    EXPECT_STRV(sql_dialect_to_string(sql_dialect::mysql), "mysql");
    EXPECT_STRV(sql_dialect_to_string(sql_dialect::pgsql), "pgsql");
    EXPECT_STRV(sql_dialect_to_string(sql_dialect::sqlite), "sqlite");
    EXPECT_STRV(sql_dialect_to_string(sql_dialect::oracle), "oracle");
    EXPECT_STRV(sql_dialect_to_string(sql_dialect::doctrine), "doctrine");
    EXPECT_STRV(sql_dialect_to_string(sql_dialect::hsqldb), "hsqldb");
    EXPECT_STRV(sql_dialect_to_string(sql_dialect::generic), "generic");
}

TEST(TestGenericTokenizer, DialectOstream)
{
    auto stream_dialect = [](auto dialect) {
        std::stringstream ss;
        ss << dialect;
        return ss.str();
    };

    EXPECT_STR(stream_dialect(sql_dialect::mysql), "mysql");
    EXPECT_STR(stream_dialect(sql_dialect::pgsql), "pgsql");
    EXPECT_STR(stream_dialect(sql_dialect::sqlite), "sqlite");
    EXPECT_STR(stream_dialect(sql_dialect::oracle), "oracle");
    EXPECT_STR(stream_dialect(sql_dialect::doctrine), "doctrine");
    EXPECT_STR(stream_dialect(sql_dialect::hsqldb), "hsqldb");
    EXPECT_STR(stream_dialect(sql_dialect::generic), "generic");
}

TEST(TestGenericTokenizer, TokenTypeOstream)
{
    auto stream_token = [](auto token) {
        std::stringstream ss;
        ss << token;
        return ss.str();
    };

    EXPECT_STR(stream_token(sql_token_type::unknown), "unknown");
    EXPECT_STR(stream_token(sql_token_type::keyword), "keyword");
    EXPECT_STR(stream_token(sql_token_type::identifier), "identifier");
    EXPECT_STR(stream_token(sql_token_type::number), "number");
    EXPECT_STR(stream_token(sql_token_type::string), "string");
    EXPECT_STR(stream_token(sql_token_type::single_quoted_string), "single_quoted_string");
    EXPECT_STR(stream_token(sql_token_type::double_quoted_string), "double_quoted_string");
    EXPECT_STR(stream_token(sql_token_type::back_quoted_string), "back_quoted_string");
    EXPECT_STR(stream_token(sql_token_type::dollar_quoted_string), "dollar_quoted_string");
    EXPECT_STR(stream_token(sql_token_type::whitespace), "whitespace");
    EXPECT_STR(stream_token(sql_token_type::asterisk), "asterisk");
    EXPECT_STR(stream_token(sql_token_type::eol_comment), "eol_comment");
    EXPECT_STR(stream_token(sql_token_type::parenthesis_open), "parenthesis_open");
    EXPECT_STR(stream_token(sql_token_type::parenthesis_close), "parenthesis_close");
    EXPECT_STR(stream_token(sql_token_type::comma), "comma");
    EXPECT_STR(stream_token(sql_token_type::questionmark), "questionmark");
    EXPECT_STR(stream_token(sql_token_type::colon), "colon");
    EXPECT_STR(stream_token(sql_token_type::dot), "dot");
    EXPECT_STR(stream_token(sql_token_type::query_end), "query_end");
    EXPECT_STR(stream_token(sql_token_type::binary_operator), "binary_operator");
    EXPECT_STR(stream_token(sql_token_type::bitwise_operator), "bitwise_operator");
    EXPECT_STR(stream_token(sql_token_type::inline_comment), "inline_comment");
    EXPECT_STR(stream_token(sql_token_type::array_open), "array_open");
    EXPECT_STR(stream_token(sql_token_type::array_close), "array_close");
    EXPECT_STR(stream_token(sql_token_type::curly_brace_open), "curly_brace_open");
    EXPECT_STR(stream_token(sql_token_type::curly_brace_close), "curly_brace_close");
}

TEST(TestGenericTokenizer, Commands)
{
    std::vector<std::string> samples{
        "SELECT", "FROM", "WHERE", "GROUP", "BY", "OFFSET", "LIMIT", "ORDER", "BY", "ASC", "DESC"};

    for (const auto &statement : samples) {
        {
            generic_sql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::keyword) << statement;
        }

        {
            auto lc_statement = str_to_lower(statement);
            generic_sql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::keyword);
        }
    }
}

TEST(TestGenericTokenizer, Identifiers)
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

TEST(TestGenericTokenizer, Number)
{
    std::vector<std::string> samples{"0", "1.1", "1", "1", "1e17", "1.0101e+17", "0x22", "0xFF",
        "0122", "00", "0b101", "0B11_00", "0b110_0", "0X12_3", "0xFA_AA", "0o77", "0O7_7",
        "012_345", "0.000_00", "-1.2", "-0.1", "-1", "+1", "+1.2", "+0.1"};

    for (const auto &statement : samples) {
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::number) << statement;
    }
}

TEST(TestGenericTokenizer, BinaryOperators)
{
    // Asterisk is a special case
    std::vector<std::string> samples{"+", "-", "/", "%", "=", "!=", "<>", "<", ">",
        ">=", "<=", "||", "OR", "AND", "BETWEEN", "LIKE", "IN", "MOD", "IS", "NOT"};

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

TEST(TestGenericTokenizer, BitwiseOperators)
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

TEST(TestGenericTokenizer, Expression)
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
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        // ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestGenericTokenizer, InlineComment)
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
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestGenericTokenizer, EolComment)
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
        generic_sql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestGenericTokenizer, DoubleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"("this is a string")", {stt::identifier}},
        {R"("this is \"quoted\" string")", {stt::identifier}},
        {R"("this is \\\\\"quoted\" string")", {stt::identifier}},
        {R"("this \n is \\\\\"quoted\\\\\" string")", {stt::identifier}},
        {R"("this is \"quoted\" string" and "another string")",
            {stt::identifier, stt::binary_operator, stt::identifier}},
        {R"("this is an unterminated string)", {stt::identifier}},
        {R"(SELECT "colname")", {stt::keyword, stt::identifier}},
        {R"("colname" FROM)", {stt::identifier, stt::keyword}},
        {R"(SELECT "colname" FROM "table";)",
            {stt::keyword, stt::identifier, stt::keyword, stt::identifier, stt::query_end}},
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

TEST(TestGenericTokenizer, SingleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"('this is a string')", {stt::single_quoted_string}},
        {R"('this is \'quoted\' string')", {stt::single_quoted_string}},
        {R"('this is \\\\\'quoted\' string')", {stt::single_quoted_string}},
        {R"('this \n is \\\\\'quoted\\\\\' string')", {stt::single_quoted_string}},
        {R"('this is \'quoted\' string' and 'another string')",
            {stt::single_quoted_string, stt::binary_operator, stt::single_quoted_string}},
        {R"('this is an unterminated string)", {stt::single_quoted_string}},
        {R"(SELECT 'colname')", {stt::keyword, stt::single_quoted_string}},
        {R"('colname' FROM)", {stt::single_quoted_string, stt::keyword}},
        {R"('colname''what' FROM)", {stt::single_quoted_string, stt::keyword}},
        {R"('colname\\''what' FROM)", {stt::single_quoted_string, stt::keyword}},
        {R"('colname\'what FROM)", {stt::single_quoted_string}},
        {R"(SELECT 'colname' FROM 'table';)",
            {stt::keyword, stt::single_quoted_string, stt::keyword, stt::single_quoted_string,
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

TEST(TestGenericTokenizer, BacktickQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(`this is a string`)", {stt::back_quoted_string}},
        {R"(`this is \`quoted\` string`)", {stt::back_quoted_string}},
        {R"(`this is \\\\\`quoted\` string`)", {stt::back_quoted_string}},
        {R"(`this \n is \\\\\`quoted\\\\\` string`)", {stt::back_quoted_string}},
        {R"(`this is \`quoted\` string` and `another string`)",
            {stt::back_quoted_string, stt::binary_operator, stt::back_quoted_string}},
        {R"(`this is an unterminated string)", {stt::back_quoted_string}},
        {R"(SELECT `colname`)", {stt::keyword, stt::back_quoted_string}},
        {R"(`colname` FROM)", {stt::back_quoted_string, stt::keyword}},
        {R"(SELECT `colname` FROM `table`;)", {stt::keyword, stt::back_quoted_string, stt::keyword,
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

TEST(TestGenericTokenizer, Queries)
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

        {R"(SELECT name FROM (SELECT * FROM generic_master UNION ALL SELECT * FROM generic_temp_master) WHERE type='table' ORDER BY name)",
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

        // https://www.generic.org/faq.html (14)
        {R"(SELECT  1 FROM u WHERE mail = 'vega@example.com\\''' LIMIT 1 ;)",
            {stt::keyword, stt::number, stt::keyword, stt::identifier, stt::keyword,
                stt::identifier, stt::binary_operator, stt::single_quoted_string, stt::keyword,
                stt::number, stt::query_end}},

        {R"(label: SELECT * FROM productLine WHERE model = 'MacPro 2013' /*randomgarbage')",
            {stt::identifier, stt::colon, stt::keyword, stt::asterisk, stt::keyword,
                stt::identifier, stt::keyword, stt::identifier, stt::binary_operator,
                stt::single_quoted_string, stt::inline_comment}}};

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
