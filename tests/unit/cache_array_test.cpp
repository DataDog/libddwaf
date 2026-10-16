// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstddef>
#include <utility>

#include "cache_array.hpp"
#include "memory_resource.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

struct entry {
    int value{0};
    memory::vector<int> values;
};

TEST(TestCacheArray, OwnedArray)
{
    cache_array<entry> array{3};
    EXPECT_FALSE(array.is_derived());
    EXPECT_EQ(array.size(), 3);

    array.get_writable(1).value = 5;
    EXPECT_EQ(std::as_const(array).get(0).value, 0);
    EXPECT_EQ(std::as_const(array).get(1).value, 5);
    EXPECT_EQ(std::as_const(array).get(2).value, 0);

    array.resize(4);
    EXPECT_EQ(array.size(), 4);
    EXPECT_EQ(std::as_const(array).get(1).value, 5);
    EXPECT_EQ(std::as_const(array).get(3).value, 0);
}

TEST(TestCacheArray, DerivedArrayReadsUpstream)
{
    cache_array<entry> upstream{3};
    upstream.get_writable(0).value = 1;
    upstream.get_writable(2).value = 3;

    auto derived = cache_array<entry>::derive(upstream);
    EXPECT_TRUE(derived.is_derived());
    EXPECT_EQ(derived.size(), 3);
    EXPECT_EQ(&std::as_const(derived).get(0), &std::as_const(upstream).get(0));
    EXPECT_EQ(std::as_const(derived).get(0).value, 1);
    EXPECT_EQ(std::as_const(derived).get(1).value, 0);
    EXPECT_EQ(std::as_const(derived).get(2).value, 3);
}

TEST(TestCacheArray, DerivedArrayCopiesOnWrite)
{
    cache_array<entry> upstream{4};
    upstream.get_writable(1).value = 1;
    upstream.get_writable(1).values = {1, 2};
    upstream.get_writable(3).value = 3;

    auto derived = cache_array<entry>::derive(upstream);

    // The copy starts from the upstream entry
    auto &writable = derived.get_writable(1);
    EXPECT_EQ(writable.value, 1);
    EXPECT_EQ(writable.values, (memory::vector<int>{1, 2}));
    writable.value = 10;
    writable.values.emplace_back(3);

    EXPECT_EQ(std::as_const(derived).get(1).value, 10);
    EXPECT_EQ(std::as_const(derived).get(1).values, (memory::vector<int>{1, 2, 3}));
    EXPECT_NE(&std::as_const(derived).get(1), &std::as_const(upstream).get(1));

    // The upstream entry is unchanged
    EXPECT_EQ(std::as_const(upstream).get(1).value, 1);
    EXPECT_EQ(std::as_const(upstream).get(1).values, (memory::vector<int>{1, 2}));

    // Writing the same entry again doesn't copy it again
    derived.get_writable(1).value = 11;
    EXPECT_EQ(std::as_const(derived).get(1).value, 11);
    EXPECT_EQ(std::as_const(derived).get(1).values, (memory::vector<int>{1, 2, 3}));

    // Other entries are still read from upstream
    EXPECT_EQ(&std::as_const(derived).get(3), &std::as_const(upstream).get(3));
}

TEST(TestCacheArray, DerivedArrayWritesInAnyOrder)
{
    constexpr std::size_t size = 20;
    cache_array<entry> upstream{size};
    for (std::size_t i = 0; i < size; ++i) { upstream.get_writable(i).value = static_cast<int>(i); }

    auto derived = cache_array<entry>::derive(upstream);
    for (const std::size_t i : {7, 3, 15, 0, 19, 8, 4, 11}) {
        derived.get_writable(i).value += 100;
    }

    for (std::size_t i = 0; i < size; ++i) {
        const bool written =
            i == 0 || i == 3 || i == 4 || i == 7 || i == 8 || i == 11 || i == 15 || i == 19;
        EXPECT_EQ(std::as_const(derived).get(i).value, static_cast<int>(i) + (written ? 100 : 0));
        EXPECT_EQ(std::as_const(upstream).get(i).value, static_cast<int>(i));
    }
}

TEST(TestCacheArray, DerivedArrayWithCapacity)
{
    constexpr std::size_t size = 6;
    cache_array<entry> upstream{size};
    for (std::size_t i = 0; i < size; ++i) { upstream.get_writable(i).value = static_cast<int>(i); }

    // A capacity beyond the size of the array is limited to it
    auto derived = cache_array<entry>::derive(upstream, size * 2);
    for (const std::size_t i : {0, 1, 3, 5, 2, 4}) {
        derived.get_writable(i).values.emplace_back(static_cast<int>(i));
    }

    for (std::size_t i = 0; i < size; ++i) {
        EXPECT_EQ(std::as_const(derived).get(i).value, static_cast<int>(i));
        EXPECT_EQ(std::as_const(derived).get(i).values, (memory::vector<int>{static_cast<int>(i)}));
        EXPECT_TRUE(std::as_const(upstream).get(i).values.empty());
    }
}

TEST(TestCacheArray, MultipleDerivedArrays)
{
    cache_array<entry> upstream{2};
    upstream.get_writable(0).value = 1;

    auto first = cache_array<entry>::derive(upstream);
    auto second = cache_array<entry>::derive(upstream);

    first.get_writable(0).value = 2;
    second.get_writable(0).value = 3;

    EXPECT_EQ(std::as_const(upstream).get(0).value, 1);
    EXPECT_EQ(std::as_const(first).get(0).value, 2);
    EXPECT_EQ(std::as_const(second).get(0).value, 3);
}

} // namespace
