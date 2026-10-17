// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstddef>
#include <cstdint>

#include "matcher/base.hpp"
#include "matcher/equals.hpp"
#include "matcher/greater_than.hpp"
#include "matcher/regex_match.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {

using type_set = matcher::base::type_set;

TEST(TestMatcherTypeSet, EmptyPredicate)
{
    constexpr auto set = type_set::from_predicate([](object_type) { return false; });
    for (std::size_t i = 0; i <= UINT8_MAX; ++i) {
        EXPECT_FALSE(set.contains(static_cast<object_type>(i))) << i;
    }
}

TEST(TestMatcherTypeSet, FullPredicate)
{
    constexpr auto set = type_set::from_predicate([](object_type) { return true; });
    for (std::size_t i = 0; i <= UINT8_MAX; ++i) {
        EXPECT_TRUE(set.contains(static_cast<object_type>(i))) << i;
    }
}

TEST(TestMatcherTypeSet, EveryValueMatchesPredicate)
{
    // Covers every bit of every word, including the first and last values
    auto pred = [](object_type type) {
        auto v = static_cast<std::size_t>(type);
        return v % 3 == 0 || v == 63 || v == 64 || v == 255;
    };
    const auto set = type_set::from_predicate(pred);
    for (std::size_t i = 0; i <= UINT8_MAX; ++i) {
        EXPECT_EQ(set.contains(static_cast<object_type>(i)), pred(static_cast<object_type>(i)))
            << i;
    }
}

TEST(TestMatcherTypeSet, StringTypes)
{
    constexpr auto set =
        type_set::from_predicate([](object_type type) { return (type & object_type::string) != 0; });
    EXPECT_TRUE(set.contains(object_type::string));
    EXPECT_TRUE(set.contains(object_type::literal_string));
    EXPECT_TRUE(set.contains(object_type::small_string));
    EXPECT_FALSE(set.contains(object_type::invalid));
    EXPECT_FALSE(set.contains(object_type::null));
    EXPECT_FALSE(set.contains(object_type::boolean));
    EXPECT_FALSE(set.contains(object_type::int64));
    EXPECT_FALSE(set.contains(object_type::uint64));
    EXPECT_FALSE(set.contains(object_type::float64));
    EXPECT_FALSE(set.contains(object_type::array));
    EXPECT_FALSE(set.contains(object_type::map));
    EXPECT_FALSE(set.contains(object_type::hash_map));
    EXPECT_FALSE(set.contains(object_type::large_array));
    EXPECT_FALSE(set.contains(object_type::large_map));
}

TEST(TestMatcherTypeSet, MatcherSupportedTypes)
{
    const matcher::regex_match regex{"abc", 1, true};
    const matcher::equals<bool> equals_bool{true};
    const matcher::greater_than<double> gt_double{1.0};

    // Supported types through the base class, as used by conditions
    const matcher::base &regex_base = regex;
    EXPECT_TRUE(regex_base.is_supported_type(object_type::string));
    EXPECT_TRUE(regex_base.is_supported_type(object_type::small_string));
    EXPECT_TRUE(regex_base.is_supported_type(object_type::literal_string));
    EXPECT_FALSE(regex_base.is_supported_type(object_type::int64));
    EXPECT_FALSE(regex_base.is_supported_type(object_type::map));

    const matcher::base &equals_bool_base = equals_bool;
    EXPECT_TRUE(equals_bool_base.is_supported_type(object_type::boolean));
    EXPECT_FALSE(equals_bool_base.is_supported_type(object_type::string));
    EXPECT_FALSE(equals_bool_base.is_supported_type(object_type::int64));

    const matcher::base &gt_double_base = gt_double;
    EXPECT_TRUE(gt_double_base.is_supported_type(object_type::float64));
    EXPECT_TRUE(gt_double_base.is_supported_type(object_type::int64));
    EXPECT_TRUE(gt_double_base.is_supported_type(object_type::uint64));
    EXPECT_FALSE(gt_double_base.is_supported_type(object_type::boolean));
    EXPECT_FALSE(gt_double_base.is_supported_type(object_type::string));
}

} // namespace
