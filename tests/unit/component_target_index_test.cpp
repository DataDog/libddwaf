// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "component_target_index.hpp"
#include "target_address.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

using component_set = component_target_index::component_set;

std::vector<component_set> to_vector(std::span<const component_set> sets)
{
    return {sets.begin(), sets.end()};
}

// The i-th element contains the targets referenced by the i-th component
component_target_index make_index(const std::vector<std::vector<target_index>> &targets)
{
    std::vector<component_target_index::reference> references;
    for (std::size_t i = 0; i < targets.size(); ++i) {
        for (const auto target : targets[i]) {
            references.push_back({.target = target, .component = i});
        }
    }
    return component_target_index{std::move(references)};
}

TEST(TestComponentTargetIndex, Empty)
{
    component_target_index index;
    EXPECT_TRUE(index.find(0).empty());

    auto from_empty = make_index({});
    EXPECT_TRUE(from_empty.find(0).empty());

    auto without_targets = make_index({{}, {}});
    EXPECT_TRUE(without_targets.find(0).empty());
}

TEST(TestComponentTargetIndex, ComponentsByTarget)
{
    auto index = make_index({{1, 3}, {3}, {}, {1, 4}});

    EXPECT_TRUE(index.find(0).empty());
    EXPECT_EQ(to_vector(index.find(1)), (std::vector<component_set>{{0, 0b1001}}));
    EXPECT_TRUE(index.find(2).empty());
    EXPECT_EQ(to_vector(index.find(3)), (std::vector<component_set>{{0, 0b0011}}));
    EXPECT_EQ(to_vector(index.find(4)), (std::vector<component_set>{{0, 0b1000}}));
    EXPECT_TRUE(index.find(5).empty());
    EXPECT_TRUE(index.find(1000).empty());
}

TEST(TestComponentTargetIndex, ComponentsAcrossWords)
{
    std::vector<std::vector<target_index>> targets(130);
    targets[0] = {7};
    targets[63] = {7};
    targets[64] = {7, 2};
    targets[129] = {7};

    auto index = make_index(targets);
    EXPECT_EQ(to_vector(index.find(7)), (std::vector<component_set>{{0, (uint64_t{1} << 63) | 1},
                                            {1, 1}, {2, uint64_t{1} << 1}}));
    EXPECT_EQ(to_vector(index.find(2)), (std::vector<component_set>{{1, 1}}));
}

TEST(TestComponentTargetIndex, UnorderedAndDuplicateReferences)
{
    component_target_index index{{{.target = 2, .component = 70}, {.target = 5, .component = 1},
        {.target = 2, .component = 3}, {.target = 2, .component = 70},
        {.target = 2, .component = 0}, {.target = 5, .component = 1}}};

    EXPECT_EQ(to_vector(index.find(2)),
        (std::vector<component_set>{{0, 0b1001}, {1, uint64_t{1} << 6}}));
    EXPECT_EQ(to_vector(index.find(5)), (std::vector<component_set>{{0, 0b10}}));
    EXPECT_TRUE(index.find(3).empty());
}

TEST(TestComponentBitset, Empty)
{
    component_bitset bitset;
    EXPECT_FALSE(bitset.test(0));

    component_bitset empty{0};
    EXPECT_FALSE(empty.test(0));
}

TEST(TestComponentBitset, InitiallySet)
{
    for (std::size_t count : {1, 5, 63, 64, 65, 128, 130}) {
        component_bitset bitset{count};
        for (std::size_t i = 0; i < count; ++i) { EXPECT_TRUE(bitset.test(i)) << count; }

        // Bits past the count, within the last word, are clear
        for (std::size_t i = count; i % 64 != 0; ++i) { EXPECT_FALSE(bitset.test(i)) << count; }
    }
}

TEST(TestComponentBitset, ResetAndSet)
{
    std::vector<std::vector<target_index>> targets(130);
    targets[1] = {0};
    targets[64] = {0};
    targets[129] = {1};
    auto index = make_index(targets);

    component_bitset bitset{130};
    for (std::size_t i = 0; i < 130; ++i) { bitset.reset(i); }
    for (std::size_t i = 0; i < 130; ++i) { EXPECT_FALSE(bitset.test(i)); }

    bitset.set(index.find(0));
    for (std::size_t i = 0; i < 130; ++i) { EXPECT_EQ(bitset.test(i), i == 1 || i == 64); }

    bitset.set(index.find(1));
    bitset.set(index.find(2));
    for (std::size_t i = 0; i < 130; ++i) {
        EXPECT_EQ(bitset.test(i), i == 1 || i == 64 || i == 129);
    }

    bitset.reset(64);
    for (std::size_t i = 0; i < 130; ++i) { EXPECT_EQ(bitset.test(i), i == 1 || i == 129); }
}

TEST(TestComponentBitset, CopiesAreIndependent)
{
    component_bitset bitset{70};
    bitset.reset(3);

    auto copy = bitset;
    copy.reset(4);
    copy.reset(68);

    EXPECT_FALSE(bitset.test(3));
    EXPECT_TRUE(bitset.test(4));
    EXPECT_TRUE(bitset.test(68));
    EXPECT_FALSE(copy.test(3));
    EXPECT_FALSE(copy.test(4));
    EXPECT_FALSE(copy.test(68));
}

} // namespace
