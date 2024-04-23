// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "condition/sqli_detector.hpp"
#include "test_utils.hpp"
#include "tokenizer/generic_sql.hpp"
#include "tokenizer/pgsql.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(TestSqliDetectorInternals, HasOrderByStructureSuccess)
{
    std::vector<std::string> samples{
        "1",
        "table",
        "table.col",
        R"("table")",
        R"("table"."col")",
        "'table'",
        "'table'.'col'",
        "`table`",
        "`table`.`col`",
        "1, 2",
        "1, 2, 3, 4",
        "1, table",
        "1, table.col, table, other",
        "table, 1, 2, other.col",
        "table.col, 1, 2, 3, other",
        "1 ASC",
        "1 desc",
        "1 desc, 2",
        "1 DESC, 2 ASC",
        "122 DESC LIMIT 20",
        "122 DESC LIMIT 20 OFFSET 50",
        "table ASC",
        "table desc",
        "table desc, 2",
        "table DESC, 2 ASC",
        "table desc, other",
        "table DESC, other ASC",
        "table DESC LIMIT 20",
        "table DESC LIMIT 20 OFFSET 50",
        "table.col ASC",
        "table.col desc",
        "table.col desc, 2",
        "table.col DESC, 2 ASC",
        "table.col desc, other",
        "table.col DESC, other ASC",
        "table.col desc, other.col",
        "table.col DESC, other.col ASC",
        "table.col DESC LIMIT 20",
        "table.col DESC LIMIT 20 OFFSET 50",
    };

    for (const auto &sample : samples) {
        pgsql_tokenizer tokenizer(sample);
        auto tokens = tokenizer.tokenize();

        EXPECT_TRUE(internal::has_order_by_structure(tokens)) << sample;
    }
}

TEST(TestSqliDetectorInternals, HasOrderByStructureFailure)
{
    std::vector<std::string> samples{
        ",", "., 2", "LIMIT", "10 LIMIT table", "SELECT", "table table", "OFFSET",
        "20 OFFSET table",
        "20 OFFSET 5;" // The Order By injection terminates the statement
    };

    for (const auto &sample : samples) {
        pgsql_tokenizer tokenizer(sample);
        auto tokens = tokenizer.tokenize();

        EXPECT_FALSE(internal::has_order_by_structure(tokens)) << sample;
    }
}

TEST(TestSqliDetectorInternals, IsBenignOrderByClauseSuccess)
{
    std::vector<std::string> samples{
        "1",
        "1, 2",
        "1, 2, 3, 4",
        "1, table",
        "1, table.col, table, other",
        "table, 1, 2, other.col",
        "table.col, 1, 2, 3, other",
        "1 ASC",
        "1 desc",
        "1 desc, 2",
        "1 DESC, 2 ASC",
        "122 DESC LIMIT 20",
        "122 DESC LIMIT 20 OFFSET 50",
        "table ASC",
        "table desc",
        "table desc, 2",
        "table DESC, 2 ASC",
        "table desc, other",
        "table DESC, other ASC",
        "table DESC LIMIT 20",
        "table DESC LIMIT 20 OFFSET 50",
        "table.col ASC",
        "table.col desc",
        "table.col desc, 2",
        "table.col DESC, 2 ASC",
        "table.col desc, other",
        "table.col DESC, other ASC",
        "table.col desc, other.col",
        "table.col DESC, other.col ASC",
        "table.col DESC LIMIT 20",
        "table.col DESC LIMIT 20 OFFSET 50",
    };

    for (const auto &sample : samples) {
        auto statement = "ORDER BY " + sample;
        pgsql_tokenizer tokenizer(statement);
        auto resource_tokens = tokenizer.tokenize();

        EXPECT_STRV(resource_tokens[0].str, "ORDER BY");

        std::span<sql_token> param_tokens{&resource_tokens[1], resource_tokens.size() - 1};
        auto res = internal::is_benign_order_by_clause(resource_tokens, param_tokens, 1);
        EXPECT_TRUE(res) << sample;
    }
}

TEST(TestSqliDetectorInternals, IsBenignOrderByClauseNotAnOrderBy)
{
    std::string statement = "SELECT table desc";
    pgsql_tokenizer tokenizer(statement);
    auto resource_tokens = tokenizer.tokenize();

    std::span<sql_token> param_tokens{&resource_tokens[1], resource_tokens.size() - 1};
    auto res = internal::is_benign_order_by_clause(resource_tokens, param_tokens, 1);
    EXPECT_FALSE(res);
}

TEST(TestSqliDetectorInternals, IsBenignOrderByClauseNotEnoughTokens)
{
    std::string statement = "table desc";
    pgsql_tokenizer tokenizer(statement);
    auto resource_tokens = tokenizer.tokenize();

    auto res = internal::is_benign_order_by_clause(resource_tokens, resource_tokens, 0);
    EXPECT_FALSE(res);
}

TEST(TestSqliDetectorInternals, IsWhereTautologySuccess)
{
    std::vector<std::pair<std::string, std::string>> samples{
        {"SELECT x FROM t WHERE id = 1 OR 1", "1 OR 1"},
        {"SELECT x FROM t WHERE id = 1 OR tbl", "1 OR tbl"},
        {"SELECT x FROM t WHERE id = tbl OR tbl", "tbl OR tbl"},
        {"SELECT x FROM t WHERE id = tbl OR tbl", "tbl OR tbl"},
        {R"(SELECT x FROM t WHERE id = ""OR"")", R"("OR")"},
        {"SELECT x FROM t WHERE id = ''OR''", "'OR'"},
        {"SELECT x FROM t WHERE id = 1||tbl", "1||tbl"},
        {"SELECT x FROM t WHERE id = tbl||tbl", "tbl||tbl"},
        {R"(SELECT x FROM t WHERE id = ""||"")", R"("||")"},
        {"SELECT x FROM t WHERE id = 1 XOR 1", "1 XOR 1"},
        {R"(SELECT x FROM t WHERE id = tbl XOR tbl)", "tbl XOR tbl"},
        {R"(SELECT x FROM t WHERE id = ""XOR"")", R"("XOR")"},
        {"SELECT x FROM t WHERE id = ''Or''", "'Or'"},
        {"SELECT x FROM t WHERE id = '1' or 1 = 1", "1 = 1"},
        {"SELECT x FROM t WHERE id = '1' or 1 = '1'", "1 = '1'"},
        //{"SELECT x FROM t WHERE id = '1' or 1 = (1)", "1 = (1)"}
    };

    for (const auto &[statement, param] : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto resource_tokens = tokenizer.tokenize();

        auto param_begin = statement.find(param);
        ASSERT_NE(param_begin, std::string::npos);
        auto param_end = param_begin + param.size();

        auto [param_tokens, param_index] =
            internal::get_consecutive_tokens(resource_tokens, param_begin, param_end);

        auto res = internal::is_where_tautology(resource_tokens, param_tokens, param_index);
        EXPECT_TRUE(res) << param;
    }
}

TEST(TestSqliDetectorInternals, IsWhereTautologyFailure)
{
    std::vector<std::pair<std::string, std::string>> samples{
        {"SELECT x FROM t WHILE id = 1 OR 1", "1 OR 1"},              // No where to be found
        {"SELECT x FROM t WHERE id = 1 OAR tbl", "1 OAR tbl"},        // Sea dialect not recognized
        {"SELECT x FROM t WHERE id = '1' or table = 1", "table = 1"}, // Unclear tautology
        {"SELECT x FROM t WHERE id = '1' or table", "table"},         // Not enough tokens
        {"1 OR 1", "1 OR 1"},                                         // Malformed
        {"SELECT 1 OR 1 WHERE", "1 OR 1"},                            // Tautology before WHERE
    };

    for (const auto &[statement, param] : samples) {
        pgsql_tokenizer tokenizer(statement);
        auto resource_tokens = tokenizer.tokenize();

        auto param_begin = statement.find(param);
        ASSERT_NE(param_begin, std::string::npos);
        auto param_end = param_begin + param.size();

        auto [param_tokens, param_index] =
            internal::get_consecutive_tokens(resource_tokens, param_begin, param_end);

        auto res = internal::is_where_tautology(resource_tokens, param_tokens, param_index);
        EXPECT_FALSE(res) << param;
    }
}

TEST(TestSqliDetectorInternals, IsQueryCommentSuccess)
{
    std::vector<std::pair<std::string, std::string>> samples{
        {R"(SELECT x FROM t WHERE id='admin'#)", R"(admin'#)"},
        {R"(SELECT x FROM t WHERE id='admin')#)", R"(admin')#)"},
        {R"(SELECT x FROM t WHERE id=1-- )", R"(1-- )"},
        {R"(SELECT * FROM ships WHERE id= 1 # AND password=HASH('str') 1 # )", R"( 1 # )"},
        {R"(SELECT * FROM ships WHERE id= 1 --AND password=HASH('str') 1 --)", R"( 1 --)"},
        {R"(SELECT x FROM t WHERE id=''-- AND pwd='pwd'''--)", R"('--)"},
        {R"(SELECT * FROM ships WHERE id= 1 # AND password=HASH('str') 1 # )", R"( 1 # )"},
    };

    for (const auto &[statement, param] : samples) {
        generic_sql_tokenizer tokenizer(statement);
        auto resource_tokens = tokenizer.tokenize();

        auto param_begin = statement.find(param);
        ASSERT_NE(param_begin, std::string::npos);
        auto param_end = param_begin + param.size();

        auto [param_tokens, param_index] =
            internal::get_consecutive_tokens(resource_tokens, param_begin, param_end);

        EXPECT_TRUE(internal::is_query_comment(param_tokens));
    }
}

} // namespace
