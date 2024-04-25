// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <unordered_map>

#include "regex_utils.hpp"
#include "test.hpp"

using namespace ddwaf;

namespace {

TEST(TestRegexUtils, RegexInitThrow)
{
    auto valid_regex = regex_init("^[0-9]+$");
    ASSERT_NE(valid_regex, nullptr);
    ASSERT_TRUE(valid_regex->ok());

    EXPECT_THROW(regex_init("$][^"), std::runtime_error);
}

TEST(TestRegexUtils, RegexInitNoThrow)
{
    auto valid_regex = regex_init_nothrow("^[0-9]+$");
    ASSERT_NE(valid_regex, nullptr);
    ASSERT_TRUE(valid_regex->ok());

    auto invalid_regex = regex_init_nothrow("$][^");
    ASSERT_EQ(invalid_regex, nullptr);
}

TEST(TestRegexUtils, RegexMatch)
{
    auto valid_regex = regex_init("^[0-9]+$");
    ASSERT_NE(valid_regex, nullptr);
    ASSERT_TRUE(valid_regex->ok());

    EXPECT_TRUE(regex_match(*valid_regex, "20"));
    EXPECT_FALSE(regex_match(*valid_regex, "hello"));
}

} // namespace
