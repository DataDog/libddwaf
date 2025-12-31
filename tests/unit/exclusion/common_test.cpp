// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "expression.hpp"
#include "object_store.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

TEST(ExclusionObjectSet, Empty)
{
    object_set excluded;
    EXPECT_TRUE(excluded.empty());
}

TEST(ExclusionObjectSet, NonEmpty)
{
    auto root = object_builder_da::map({{"value", "node"}});

    object_set excluded{root.at(0)};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 1);
    EXPECT_TRUE(excluded.contains(root.at(0)));
}

TEST(ExclusionObjectSetRef, Empty)
{
    {
        object_set_ref excluded;
        EXPECT_TRUE(excluded.empty());
    }

    {
        std::unordered_set<object_cache_key> persistent;
        object_set_ref excluded{persistent};
        EXPECT_TRUE(excluded.empty());
    }
}

TEST(ExclusionObjectSetRef, NonEmpty)
{
    auto root = object_builder_da::map({{"value", "node"}});

    std::unordered_set<object_cache_key> persistent{root.at(0)};
    object_set_ref excluded{persistent};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 1);
    EXPECT_TRUE(excluded.contains(root.at(0)));
}

} // namespace
