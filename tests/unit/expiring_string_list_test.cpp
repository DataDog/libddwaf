// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "expiring_string_list.hpp"

using namespace ddwaf;

namespace {

TEST(TestExpiringStringList, Empty)
{
    expiring_string_list list;
    EXPECT_TRUE(list.empty());
    EXPECT_EQ(list.size(), 0);
    EXPECT_EQ(list.bytes(), 0);
    EXPECT_EQ(list.begin(), list.end());
}

TEST(TestExpiringStringList, EmplaceAndIterate)
{
    expiring_string_list list;
    list.reserve(4, 16);
    list.emplace_back("first", 0);
    list.emplace_back("", 5);
    list.emplace_back(std::string(100, 'x'), 7);
    list.emplace_back("last", UINT64_MAX);

    EXPECT_FALSE(list.empty());
    EXPECT_EQ(list.size(), 4);
    EXPECT_EQ(list.bytes(), 109);

    EXPECT_EQ(list[0], expiring_string_list::value_type("first", 0));
    EXPECT_EQ(list[1], expiring_string_list::value_type("", 5));
    EXPECT_EQ(list[2], expiring_string_list::value_type(std::string(100, 'x'), 7));
    EXPECT_EQ(list[3], expiring_string_list::value_type("last", UINT64_MAX));

    std::size_t i = 0;
    for (const auto &[str, expiration] : list) {
        EXPECT_EQ(str, list[i].first);
        EXPECT_EQ(expiration, list[i].second);
        ++i;
    }
    EXPECT_EQ(i, 4);
}

TEST(TestExpiringStringList, CopyAndMove)
{
    expiring_string_list list{{"a", 1}, {"bcd", 2}};

    expiring_string_list copy{list};
    list.emplace_back("e", 3);
    ASSERT_EQ(copy.size(), 2);
    EXPECT_EQ(copy[0], expiring_string_list::value_type("a", 1));
    EXPECT_EQ(copy[1], expiring_string_list::value_type("bcd", 2));

    expiring_string_list moved{std::move(list)};
    ASSERT_EQ(moved.size(), 3);
    EXPECT_EQ(moved[2], expiring_string_list::value_type("e", 3));
}

} // namespace
