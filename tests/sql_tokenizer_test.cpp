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

TEST(TestSqlTokenizer, Basic)
{
    sql_tokenizer tokenizer(R"(SELECT x FROM t WHERE id='admin'#)");

    auto tokens = tokenizer.tokenize();

    EXPECT_EQ(tokens.size(), 9);
    EXPECT_EQ(tokens[0].type, sql_token_type::command);
    EXPECT_EQ(tokens[1].type, sql_token_type::identifier);
    EXPECT_EQ(tokens[2].type, sql_token_type::command);
    EXPECT_EQ(tokens[3].type, sql_token_type::identifier);
    EXPECT_EQ(tokens[4].type, sql_token_type::command);
    EXPECT_EQ(tokens[5].type, sql_token_type::identifier);
    EXPECT_EQ(tokens[6].type, sql_token_type::binary_operator);
    EXPECT_EQ(tokens[7].type, sql_token_type::single_quoted_string);
    EXPECT_EQ(tokens[8].type, sql_token_type::eol_comment);
}

} // namespace
