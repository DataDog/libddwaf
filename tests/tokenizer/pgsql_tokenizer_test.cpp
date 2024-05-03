// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../test_utils.hpp"
#include "tokenizer/pgsql.hpp"

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

TEST(TestPgSqlTokenizer, EnforceWordBoundaries)
{
    std::vector<std::string> samples{"NOTASC", "ASCNOT", "SELECTED", "BETWEENERS"};

    for (const auto &statement : samples) {
        {
            pgsql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::identifier);
        }

        {
            auto lc_statement = str_to_lower(statement);
            pgsql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::identifier);
        }
    }
}

TEST(TestPgSqlTokenizer, Commands)
{
    std::vector<std::string> samples{"SELECT", "FROM", "WHERE", "GROUP", "OFFSET", "LIMIT",
        "HAVING", "ORDER", "PARTITION", "BY", "ASC", "DESC", "NULL", "::"};

    for (const auto &statement : samples) {
        {
            pgsql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::keyword);
        }

        {
            auto lc_statement = str_to_lower(statement);
            pgsql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::keyword);
        }
    }
}

TEST(TestPgSqlTokenizer, Number)
{
    std::vector<std::string> samples{"0", "1.1", "1", "1", "1e17", "1.0101e+17", "0x22", "0xFF",
        "0122", "00", "0b101", "0B11_00", "0b110_0", "0X12_3", "0xFA_AA", "0o77", "0O7_7",
        "012_345", "0.000_00"};

    for (const auto &statement : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::number);
    }
}

TEST(TestPgSqlTokenizer, Identifiers)
{
    std::vector<std::string> samples{
        "ran$om", "WoR$d", "a231a234$", "asb12321321", "_a091_", "a23__$__12", "$123", "$0"};

    for (const auto &statement : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::identifier) << statement;
        EXPECT_TRUE(obtained_tokens[0].str == statement) << statement;
    }
}

TEST(TestPgSqlTokenizer, BinaryOperators)
{
    // Asterisk is a special case
    std::vector<std::string> samples{"+", "-", "/", "%", "=", "!=", "<>", "<", ">",
        ">=", "<=", "<=>", ":=", "@@", "@>", "<@", "<<", ">>", "||", "->", "->>", "?|", "?&", "?",
        "#>", "#>>", "#-", "OR", "XOR", "AND", "IN", "BETWEEN", "LIKE", "REGEXP", "SOUNDS", "LIKE",
        "NOT", "IS", "MOD", "DIV"};

    for (const auto &statement : samples) {
        {
            pgsql_tokenizer tokenizer(statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::binary_operator);
        }

        {
            auto lc_statement = str_to_lower(statement);
            pgsql_tokenizer tokenizer(lc_statement);
            auto obtained_tokens = tokenizer.tokenize();
            ASSERT_EQ(obtained_tokens.size(), 1) << statement;
            EXPECT_EQ(obtained_tokens[0].type, stt::binary_operator);
        }
    }
}

TEST(TestPgSqlTokenizer, BitwiseOperators)
{
    std::vector<std::string> samples{"&", "^", "|", "~"};

    for (const auto &statement : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(obtained_tokens.size(), 1) << statement;
        EXPECT_EQ(obtained_tokens[0].type, stt::bitwise_operator);
        EXPECT_TRUE(obtained_tokens[0].str == statement);
    }
}

TEST(TestPgSqlTokenizer, InlineComment)
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
        pgsql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestPgSqlTokenizer, EolComment)
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
        pgsql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestPgSqlTokenizer, DoubleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"("this is a string")", {stt::identifier}},
        {R"("this is \"quoted\" string")", {stt::identifier}},
        {R"("this is \"quoted\" string" and "another string")",
            {stt::identifier, stt::binary_operator, stt::identifier}},
        {R"("this is an unterminated string)", {stt::identifier}},
        {R"(SELECT "colname")", {stt::keyword, stt::identifier}},
        {R"("colname" FROM)", {stt::identifier, stt::keyword}},
        {R"(SELECT "colname" FROM "table";)",
            {stt::keyword, stt::identifier, stt::keyword, stt::identifier, stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestPgSqlTokenizer, SingleQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"('this is a string')", {stt::single_quoted_string}},
        {R"('this is \'quoted\' string')", {stt::single_quoted_string}},
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
        pgsql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestPgSqlTokenizer, BacktickQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"(`this is a string`)", {stt::back_quoted_string}},
        {R"(`this is \`quoted\` string`)", {stt::back_quoted_string}},
        {R"(`this is \`quoted\` string` and `another string`)",
            {stt::back_quoted_string, stt::binary_operator, stt::back_quoted_string}},
        {R"(`this is an unterminated string)", {stt::back_quoted_string}},
        {R"(SELECT `colname`)", {stt::keyword, stt::back_quoted_string}},
        {R"(`colname` FROM)", {stt::back_quoted_string, stt::keyword}},
        {R"(SELECT `colname` FROM `table`;)", {stt::keyword, stt::back_quoted_string, stt::keyword,
                                                  stt::back_quoted_string, stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestPgSqlTokenizer, DolllarQuotedString)
{
    std::vector<std::pair<std::string, std::vector<stt>>> samples{
        {R"($$this is a string$$)", {stt::dollar_quoted_string}},
        {R"($tag$this is $$inner tag$$ string$tag$)", {stt::dollar_quoted_string}},
        {R"($_tag11$this is $$inner tag$$ string$_tag11$ and $$another string$$)",
            {stt::dollar_quoted_string, stt::binary_operator, stt::dollar_quoted_string}},
        {R"($unterminated$this is an unterminated string)", {stt::dollar_quoted_string}},
        {R"(SELECT $$colname$$)", {stt::keyword, stt::dollar_quoted_string}},
        {R"($tag$colname$tag$ FROM)", {stt::dollar_quoted_string, stt::keyword}},
        {R"(SELECT $$colname$$ FROM $$table$$;)",
            {stt::keyword, stt::dollar_quoted_string, stt::keyword, stt::dollar_quoted_string,
                stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type);
        }
    }
}

TEST(TestPgSqlTokenizer, Queries)
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
        {R"(SELECT DISTINCT NAME FROM TEST;)", {stt::keyword, stt::identifier, stt::identifier,
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
                stt::parenthesis_open, stt::identifier, stt::parenthesis_close, stt::identifier,
                stt::identifier, stt::keyword, stt::identifier, stt::query_end}},
        {R"(SELECT * FROM TEST LIMIT 1000;)",
            {stt::keyword, stt::asterisk, stt::keyword, stt::identifier, stt::keyword, stt::number,
                stt::query_end}},

        {R"(SELECT COUNT(*) FROM `groups` WHERE to_tsvector('fat cats ate rats') @@ to_tsquery('cat & rat'))",
            {stt::keyword, stt::identifier, stt::parenthesis_open, stt::asterisk,
                stt::parenthesis_close, stt::keyword, stt::back_quoted_string, stt::keyword,
                stt::identifier, stt::parenthesis_open, stt::single_quoted_string,
                stt::parenthesis_close, stt::binary_operator, stt::identifier,
                stt::parenthesis_open, stt::single_quoted_string, stt::parenthesis_close}},

        {R"(SELECT COUNT(*) FROM "referrers" WHERE (phones @> ARRAY['33626869936']))",
            {stt::keyword, stt::identifier, stt::parenthesis_open, stt::asterisk,
                stt::parenthesis_close, stt::keyword, stt::identifier, stt::keyword,
                stt::parenthesis_open, stt::identifier, stt::binary_operator, stt::identifier,
                stt::array_open, stt::single_quoted_string, stt::array_close,
                stt::parenthesis_close}},

        {R"(SELECT COUNT(*) FROM "referrers" WHERE (phones <@ ARRAY['33626869936']))",
            {stt::keyword, stt::identifier, stt::parenthesis_open, stt::asterisk,
                stt::parenthesis_close, stt::keyword, stt::identifier, stt::keyword,
                stt::parenthesis_open, stt::identifier, stt::binary_operator, stt::identifier,
                stt::array_open, stt::single_quoted_string, stt::array_close,
                stt::parenthesis_close}},

        {R"(   SELECT i,AVG(v::bigint) OVER (ORDER BY i ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING):tabed    )",
            {stt::keyword, stt::identifier, stt::comma, stt::identifier, stt::parenthesis_open,
                stt::identifier, stt::keyword, stt::identifier, stt::parenthesis_close,
                stt::identifier, stt::parenthesis_open, stt::keyword, stt::keyword, stt::identifier,
                stt::identifier, stt::binary_operator, stt::identifier, stt::identifier,
                stt::binary_operator, stt::identifier, stt::identifier, stt::parenthesis_close,
                stt::colon, stt::identifier}},

        {R"(SELECT depname, empno, salary, rank() OVER (PARTITION BY depname ORDER BY salary) FROM empsalary;)",
            {stt::keyword, stt::identifier, stt::comma, stt::identifier, stt::comma,
                stt::identifier, stt::comma, stt::identifier, stt::parenthesis_open,
                stt::parenthesis_close, stt::identifier, stt::parenthesis_open, stt::keyword,
                stt::keyword, stt::identifier, stt::keyword, stt::keyword, stt::identifier,
                stt::parenthesis_close, stt::keyword, stt::identifier, stt::query_end}},

        {R"(SELECT four, ten, SUM(SUM(four)) OVER (PARTITION BY four), AVG(ten) FROM tenk1
GROUP BY four, ten ORDER BY four, ten;)",
            {stt::keyword, stt::identifier, stt::comma, stt::identifier, stt::comma,
                stt::identifier, stt::parenthesis_open, stt::identifier, stt::parenthesis_open,
                stt::identifier, stt::parenthesis_close, stt::parenthesis_close, stt::identifier,
                stt::parenthesis_open, stt::keyword, stt::keyword, stt::identifier,
                stt::parenthesis_close, stt::comma, stt::identifier, stt::parenthesis_open,
                stt::identifier, stt::parenthesis_close, stt::keyword, stt::identifier,
                stt::keyword, stt::keyword, stt::identifier, stt::comma, stt::identifier,
                stt::keyword, stt::keyword, stt::identifier, stt::comma, stt::identifier,
                stt::query_end}},
        {R"(SELECT COUNT(*) OVER w FROM tenk1 WHERE unique2 < 10 WINDOW w AS ();)",
            {stt::keyword, stt::identifier, stt::parenthesis_open, stt::asterisk,
                stt::parenthesis_close, stt::identifier, stt::identifier, stt::keyword,
                stt::identifier, stt::keyword, stt::identifier, stt::binary_operator, stt::number,
                stt::identifier, stt::identifier, stt::identifier, stt::parenthesis_open,
                stt::parenthesis_close, stt::query_end}},
    };

    for (const auto &[statement, expected_tokens] : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto obtained_tokens = tokenizer.tokenize();
        ASSERT_EQ(expected_tokens.size(), obtained_tokens.size()) << statement;
        for (std::size_t i = 0; i < obtained_tokens.size(); ++i) {
            EXPECT_EQ(expected_tokens[i], obtained_tokens[i].type) << statement;
        }
    }
}

TEST(TestPgSqlTokenizer, ComplexQueries)
{
    std::vector<std::pair<std::string, std::size_t>> samples{
        {
            R"(BEGIN
                 y := x / 0;
             EXCEPTION
                 WHEN division_by_zero THEN
                     NULL;  -- ignore the error'
                 END;
        )",
            16},
        {R"(SELECT "XXX"."YYY" FROM "XXX" WHERE "XXX"."ZZZ" = $1 AND "XXX"."DDD" IN (68) AND (to_tsvector(concat(name, ',', search_terms) ) @@ to_tsquery('$$chronic$$:*'));)",
            40},
    };

    for (const auto &[statement, count] : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto tokens = tokenizer.tokenize();
        EXPECT_EQ(tokens.size(), count) << statement;
    }
}

TEST(TestPgSqlTokenizer, JsonQueries)
{
    std::vector<std::pair<std::string, std::size_t>> samples{

        {R"(SELECT '{"a":[1,2,3],"b":[4,5,6]}'::json#>>'{a,2}';)", 7},
        {R"(SELECT * FROM json_test WHERE data #>> '{b,c}' = 'd';)", 11},
        {R"(SELECT '[1,2,3]'::json->2;)", 7},
        {R"(SELECT * FROM json_test WHERE data -> 'a' > '1';)", 11},
        {R"(SELECT '{"a":1,"b":2}'::json->'b';)", 7},
        {R"(SELECT * FROM json_test WHERE data -> 'b' > '1';)", 11},
        {R"(SELECT '[1,2,3]'::json->>2;)", 7},
        {R"(SELECT * FROM json_test WHERE data ->> 'a' > '1';)", 11},
        {R"(SELECT '{"a":[1,2,3],"b":[4,5,6]}'::json#>'{a,2}';)", 7},
        {R"(SELECT * FROM json_test WHERE data #>'{a,2}';)", 9},
        {R"(SELECT * FROM json_test WHERE data @> '{"a":1}';)", 9},
        {R"(SELECT * FROM json_test WHERE data <@ '{"a":1}';)", 9},
        {R"(SELECT * FROM json_test WHERE data ? 'a';)", 9},
        {R"(select * from json_populate_recordset(null::json, '[{"a":1,"b":2},{"a":3,"b":4}]');)",
            12},
        {R"(select * from json_array_elements('[1,true, [2,false]]');)", 8},
    };

    for (const auto &[statement, count] : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto tokens = tokenizer.tokenize();
        EXPECT_EQ(tokens.size(), count) << statement;
    }
}

TEST(TestPgSqlTokenizer, TextSearchOperator)
{
    pgsql_tokenizer tokenizer("SELECT COUNT(*) FROM `groups` WHERE to_tsvector('fat cats ate "
                              "rats') @@ to_tsquery('cat & rat')");
    auto tokens = tokenizer.tokenize();

    EXPECT_EQ(tokens.size(), 17);
    EXPECT_EQ(tokens[12].type, sql_token_type::binary_operator);
}

TEST(TestPgSqlTokenizer, ArrayInclusionOperator)
{
    pgsql_tokenizer tokenizer(
        R"(SELECT COUNT(*) FROM "referrers" WHERE (phones @> ARRAY['33626869936']))");
    auto tokens = tokenizer.tokenize();

    EXPECT_EQ(tokens.size(), 16);
    EXPECT_EQ(tokens[10].type, sql_token_type::binary_operator);
}

} // namespace
