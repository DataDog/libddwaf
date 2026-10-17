// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "expiring_string_list.hpp"
#include "indexed_multivector.hpp"

#include <map>

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

TEST(TestIndexedMultivector, SingleElement)
{
    indexed_multivector<std::string, std::string> ivec;
    ASSERT_TRUE(ivec.empty());

    std::vector<std::string> vec{"a", "b", "c", "d"};
    ivec.emplace("default", vec);
    ASSERT_FALSE(ivec.empty());

    auto vec_it = vec.begin();
    for (const auto &v : ivec) {
        ASSERT_NE(vec_it, vec.end());
        EXPECT_EQ(*vec_it, v);
        ++vec_it;
    }

    ivec.erase("default");

    ASSERT_EQ(ivec.begin(), ivec.end());
    ASSERT_TRUE(ivec.empty());
}

TEST(TestIndexedMultivector, MultipleElements)
{
    indexed_multivector<std::string, std::string> ivec;
    ASSERT_TRUE(ivec.empty());

    ivec.emplace("vec1", {"a", "e", "g", "else"});
    ASSERT_FALSE(ivec.empty());

    {
        std::unordered_set<std::string> all_items{"a", "e", "g", "else"};
        for (const auto &v : ivec) {
            EXPECT_TRUE(all_items.contains(v));
            all_items.erase(v);
        }
        EXPECT_EQ(all_items.size(), 0);
    }

    ivec.emplace("vec2", {"d", "c", "long", "something"});
    ASSERT_FALSE(ivec.empty());

    {
        std::unordered_set<std::string> all_items{
            "a", "c", "d", "e", "g", "long", "something", "else"};
        for (const auto &v : ivec) {
            EXPECT_TRUE(all_items.contains(v));
            all_items.erase(v);
        }
        EXPECT_EQ(all_items.size(), 0);
    }

    ivec.emplace("vec3", {"b", "f", "string"});
    ASSERT_FALSE(ivec.empty());

    {
        std::unordered_set<std::string> all_items{
            "a", "b", "c", "d", "e", "f", "g", "long", "string", "something", "else"};
        for (const auto &v : ivec) {
            EXPECT_TRUE(all_items.contains(v));
            all_items.erase(v);
        }
        EXPECT_EQ(all_items.size(), 0);
    }

    ivec.erase("vec1");
    ASSERT_FALSE(ivec.empty());

    {
        std::unordered_set<std::string> all_items{
            "b", "c", "d", "f", "long", "string", "something"};
        for (const auto &v : ivec) {
            EXPECT_TRUE(all_items.contains(v));
            all_items.erase(v);
        }
        EXPECT_EQ(all_items.size(), 0);
    }

    ivec.erase("vec3");
    ASSERT_FALSE(ivec.empty());

    {
        std::unordered_set<std::string> all_items{"c", "d", "long", "something"};
        for (const auto &v : ivec) {
            EXPECT_TRUE(all_items.contains(v));
            all_items.erase(v);
        }
        EXPECT_EQ(all_items.size(), 0);
    }

    ivec.erase("vec2");

    ASSERT_EQ(ivec.begin(), ivec.end());
    ASSERT_TRUE(ivec.empty());
}

TEST(TestIndexedMultivector, EmptyElements)
{
    indexed_multivector<std::string, std::string> ivec;
    ivec.emplace("empty1", {});
    ASSERT_FALSE(ivec.empty());
    EXPECT_EQ(ivec.begin(), ivec.end());

    ivec.emplace("vec", {"a", "b"});
    ivec.emplace("empty2", {});

    std::unordered_set<std::string> all_items{"a", "b"};
    for (const auto &v : ivec) {
        EXPECT_TRUE(all_items.contains(v));
        all_items.erase(v);
    }
    EXPECT_EQ(all_items.size(), 0);
    EXPECT_EQ(ivec.size(), 2);
}

TEST(TestIndexedMultivector, ExpiringStringLists)
{
    indexed_multivector<std::string, expiring_string_list::value_type, expiring_string_list> ivec;
    ivec.emplace("vec1", {{"a", 1}, {"bb", 0}});
    ivec.emplace("empty", {});
    ivec.emplace("vec2", {{"ccc", 3}});
    EXPECT_EQ(ivec.size(), 3);

    std::map<std::string, uint64_t> all_items{{"a", 1}, {"bb", 0}, {"ccc", 3}};
    for (const auto &[str, expiration] : ivec) {
        auto it = all_items.find(std::string{str});
        ASSERT_NE(it, all_items.end());
        EXPECT_EQ(it->second, expiration);
        all_items.erase(it);
    }
    EXPECT_EQ(all_items.size(), 0);
}

} // namespace
