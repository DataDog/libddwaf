// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "indexed_multivector.hpp"

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

// The helpers below bound the iteration so a defective iterator makes the
// test fail instead of looping for ever.
template <typename Container>
std::vector<std::string> collect_items(const Container &ivec, std::size_t limit = 64)
{
    std::vector<std::string> items;
    for (auto it = ivec.begin(); it != ivec.end() && items.size() < limit; ++it) {
        items.emplace_back(*it);
    }
    return items;
}

// Gives the tests write access to the internal storage, so they can create
// states which emplace must never produce (empty vectors in the index).
class injectable_multivector : public indexed_multivector<std::string, std::string> {
public:
    // Inserts one empty vector per key, without using emplace
    void inject_empty(const std::vector<std::string> &keys)
    {
        for (const auto &key : keys) { data_.emplace(key, std::vector<std::string>{}); }
    }

    // Assigns payloads according to the position of each vector in the
    // iteration order of the index. No entry is inserted or erased, so the
    // order does not change.
    void assign_by_position(const std::vector<std::vector<std::string>> &payloads)
    {
        std::size_t position = 0;
        total_size_ = 0;
        for (auto &[key, vec] : data_) {
            ASSERT_LT(position, payloads.size());
            vec = payloads[position];
            total_size_ += vec.size();
            ++position;
        }
    }
};

TEST(TestIndexedMultivector, EmptyVectorAlone)
{
    indexed_multivector<std::string, std::string> ivec;

    ivec.emplace("a", {});
    EXPECT_TRUE(ivec.empty());
    EXPECT_EQ(ivec.size(), 0);
    EXPECT_EQ(ivec.begin(), ivec.end());
    EXPECT_TRUE(collect_items(ivec).empty());

    ivec.erase("a");
    EXPECT_TRUE(ivec.empty());
    EXPECT_EQ(ivec.size(), 0);
    EXPECT_EQ(ivec.begin(), ivec.end());
}

TEST(TestIndexedMultivector, EmptyVectorAfterNonEmpty)
{
    indexed_multivector<std::string, std::string> ivec;

    ivec.emplace("a", {"x", "y"});
    ivec.emplace("b", {});

    EXPECT_FALSE(ivec.empty());
    EXPECT_EQ(ivec.size(), 2);

    auto items = collect_items(ivec);
    EXPECT_THAT(items, testing::UnorderedElementsAre("x", "y"));

    ivec.erase("b");
    EXPECT_EQ(ivec.size(), 2);
    EXPECT_THAT(collect_items(ivec), testing::UnorderedElementsAre("x", "y"));

    ivec.erase("a");
    EXPECT_TRUE(ivec.empty());
    EXPECT_EQ(ivec.begin(), ivec.end());
}

TEST(TestIndexedMultivector, EmptyVectorBeforeNonEmpty)
{
    indexed_multivector<std::string, std::string> ivec;

    ivec.emplace("a", {});
    ivec.emplace("b", {"x", "y"});

    EXPECT_FALSE(ivec.empty());
    EXPECT_EQ(ivec.size(), 2);

    auto items = collect_items(ivec);
    EXPECT_THAT(items, testing::UnorderedElementsAre("x", "y"));

    ivec.erase("a");
    EXPECT_EQ(ivec.size(), 2);
    EXPECT_THAT(collect_items(ivec), testing::UnorderedElementsAre("x", "y"));
}

TEST(TestIndexedMultivector, InjectedEmptyVectorsAtAllPositions)
{
    injectable_multivector ivec;
    ivec.inject_empty({"k0", "k1", "k2", "k3", "k4", "k5", "k6"});

    // Leading (0, 1), consecutive middle (3, 4) and trailing (6) empty vectors
    ivec.assign_by_position({{}, {}, {"a", "b"}, {}, {}, {"c"}, {}});

    EXPECT_FALSE(ivec.empty());
    EXPECT_EQ(ivec.size(), 3);
    EXPECT_THAT(collect_items(ivec), testing::ElementsAre("a", "b", "c"));
}

TEST(TestIndexedMultivector, OnlyInjectedEmptyVectors)
{
    injectable_multivector ivec;
    ivec.inject_empty({"k0", "k1", "k2"});

    EXPECT_EQ(ivec.size(), 0);
    EXPECT_EQ(ivec.begin(), ivec.end());
    EXPECT_TRUE(collect_items(ivec).empty());
}

} // namespace
