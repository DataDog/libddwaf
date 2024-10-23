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
    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "value", ddwaf_object_string(&tmp, "node"));

    exclusion::object_set excluded{{&root.array[0]}, {}};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 1);
    EXPECT_TRUE(excluded.contains(&root.array[0]));

    ddwaf_object_free(&root);
}

TEST(ExclusionObjectSet, EphemeralOnly)
{
    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "value", ddwaf_object_string(&tmp, "node"));

    exclusion::object_set excluded{{}, {&root.array[0]}};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 1);
    EXPECT_TRUE(excluded.contains(&root.array[0]));

    ddwaf_object_free(&root);
}

TEST(ExclusionObjectSet, EphemeralAndPersistent)
{
    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "first", ddwaf_object_string(&tmp, "node"));
    ddwaf_object_map_add(&root, "second", ddwaf_object_string(&tmp, "node"));

    exclusion::object_set excluded{{&root.array[1]}, {&root.array[0]}};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 2);
    EXPECT_TRUE(excluded.contains(&root.array[0]));
    EXPECT_TRUE(excluded.contains(&root.array[1]));

    ddwaf_object_free(&root);
}

TEST(ExclusionObjectSetRef, Empty)
{
    {
        exclusion::object_set_ref excluded;
        EXPECT_TRUE(excluded.empty());
    }

    {
        std::unordered_set<const ddwaf_object *> persistent;
        exclusion::object_set_ref excluded{persistent, {}};
        EXPECT_TRUE(excluded.empty());
    }

    {
        std::unordered_set<const ddwaf_object *> ephemeral;
        exclusion::object_set_ref excluded{{}, ephemeral};
        EXPECT_TRUE(excluded.empty());
    }

    {
        std::unordered_set<const ddwaf_object *> persistent;
        std::unordered_set<const ddwaf_object *> ephemeral;
        exclusion::object_set_ref excluded{persistent, ephemeral};
        EXPECT_TRUE(excluded.empty());
    }
}

TEST(ExclusionObjectSetRef, PersistentOnly)
{
    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "value", ddwaf_object_string(&tmp, "node"));

    std::unordered_set<const ddwaf_object *> persistent{&root.array[0]};
    exclusion::object_set_ref excluded{persistent, {}};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 1);
    EXPECT_TRUE(excluded.contains(&root.array[0]));

    ddwaf_object_free(&root);
}

TEST(ExclusionObjectSetRef, EphemeralOnly)
{
    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "value", ddwaf_object_string(&tmp, "node"));

    std::unordered_set<const ddwaf_object *> ephemeral{&root.array[0]};
    exclusion::object_set_ref excluded{{}, ephemeral};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 1);
    EXPECT_TRUE(excluded.contains(&root.array[0]));

    ddwaf_object_free(&root);
}

TEST(ExclusionObjectSetRef, EphemeralAndPersistent)
{
    ddwaf_object tmp;
    ddwaf_object root;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "first", ddwaf_object_string(&tmp, "node"));
    ddwaf_object_map_add(&root, "second", ddwaf_object_string(&tmp, "node"));

    std::unordered_set<const ddwaf_object *> persistent{&root.array[1]};
    std::unordered_set<const ddwaf_object *> ephemeral{&root.array[0]};
    exclusion::object_set_ref excluded{persistent, ephemeral};
    EXPECT_FALSE(excluded.empty());
    EXPECT_EQ(excluded.size(), 2);
    EXPECT_TRUE(excluded.contains(&root.array[0]));
    EXPECT_TRUE(excluded.contains(&root.array[1]));

    ddwaf_object_free(&root);
}

} // namespace
