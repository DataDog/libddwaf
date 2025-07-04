// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "expression.hpp"
#include "object_store.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {

TEST(ExclusionObjectSet, Empty)
{
    exclusion::object_set excluded;
    EXPECT_TRUE(excluded.empty());
}

TEST(ExclusionObjectSet, PersistentOnly)
{
    auto root = object_builder::map({{"value", "node"}});

    exclusion::object_set excluded{{root.at(0)}, {}};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 1);
    EXPECT_TRUE(excluded.contains(root.at(0)));
}

TEST(ExclusionObjectSet, EphemeralOnly)
{
    auto root = object_builder::map({{"value", "node"}});

    exclusion::object_set excluded{{}, {root.at(0)}};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 1);
    EXPECT_TRUE(excluded.contains(root.at(0)));
}

TEST(ExclusionObjectSet, EphemeralAndPersistent)
{
    auto root = object_builder::map({{"first", "node"}, {"second", "node"}});

    exclusion::object_set excluded{{root.at(1)}, {root.at(0)}};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 2);
    EXPECT_TRUE(excluded.contains(root.at(0)));
    EXPECT_TRUE(excluded.contains(root.at(1)));
}

TEST(ExclusionObjectSetRef, Empty)
{
    {
        exclusion::object_set_ref excluded;
        EXPECT_TRUE(excluded.empty());
    }

    {
        std::unordered_set<object_view> persistent;
        exclusion::object_set_ref excluded{persistent, {}};
        EXPECT_TRUE(excluded.empty());
    }

    {
        std::unordered_set<object_view> ephemeral;
        exclusion::object_set_ref excluded{{}, ephemeral};
        EXPECT_TRUE(excluded.empty());
    }

    {
        std::unordered_set<object_view> persistent;
        std::unordered_set<object_view> ephemeral;
        exclusion::object_set_ref excluded{persistent, ephemeral};
        EXPECT_TRUE(excluded.empty());
    }
}

TEST(ExclusionObjectSetRef, PersistentOnly)
{
    auto root = object_builder::map({{"value", "node"}});

    std::unordered_set<object_view> persistent{root.at(0)};
    exclusion::object_set_ref excluded{persistent, {}};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 1);
    EXPECT_TRUE(excluded.contains(root.at(0)));
}

TEST(ExclusionObjectSetRef, EphemeralOnly)
{
    auto root = object_builder::map({{"value", "node"}});

    std::unordered_set<object_view> ephemeral{root.at(0)};
    exclusion::object_set_ref excluded{{}, ephemeral};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 1);
    EXPECT_TRUE(excluded.contains(root.at(0)));
}

TEST(ExclusionObjectSetRef, EphemeralAndPersistent)
{
    auto root = object_builder::map({{"first", "node"}, {"second", "node"}});

    std::unordered_set<object_view> persistent{root.at(1)};
    std::unordered_set<object_view> ephemeral{root.at(0)};
    exclusion::object_set_ref excluded{persistent, ephemeral};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 2);
    EXPECT_TRUE(excluded.contains(root.at(0)));
    EXPECT_TRUE(excluded.contains(root.at(1)));
}

} // namespace
