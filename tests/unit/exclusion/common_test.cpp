// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "object_store.hpp"
#include "rule.hpp"

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

core_rule make_rule(const std::string &id)
{
    return core_rule{id, id, {{"type", "type"}}, std::make_shared<expression>()};
}

TEST(ExclusionPolicy, DerivedPolicyReadsUpstream)
{
    auto rule1 = make_rule("1");
    auto rule2 = make_rule("2");
    auto root = object_builder_da::map({{"value", "node"}});

    exclusion_policy upstream;
    upstream.add_rule_exclusion(&rule1, filter_mode::monitor, {});
    upstream.add_input_exclusion(&rule2, object_set{root.at(0)});

    auto derived = exclusion_policy::derive(upstream);
    EXPECT_TRUE(derived.per_rule.empty());
    EXPECT_FALSE(derived.empty());
    EXPECT_EQ(derived.size(), 2);
    EXPECT_TRUE(derived.contains(&rule1));
    EXPECT_TRUE(derived.contains(&rule2));
    EXPECT_EQ(derived.find(&rule1).mode, filter_mode::monitor);
    EXPECT_TRUE(derived.find(&rule2).objects.contains(root.at(0)));

    // Exclusions which don't change the upstream policy aren't copied
    derived.add_rule_exclusion(&rule1, filter_mode::monitor, {});
    EXPECT_TRUE(derived.per_rule.empty());
}

TEST(ExclusionPolicy, DerivedPolicyCopiesOnWrite)
{
    auto rule1 = make_rule("1");
    auto rule2 = make_rule("2");
    auto rule3 = make_rule("3");
    auto root = object_builder_da::map({{"first", "node"}, {"second", "node"}});

    exclusion_policy upstream;
    upstream.add_rule_exclusion(&rule1, filter_mode::monitor, {});
    upstream.add_input_exclusion(&rule2, object_set{root.at(0)});

    auto derived = exclusion_policy::derive(upstream);
    derived.add_rule_exclusion(&rule1, filter_mode::bypass, {});
    derived.add_input_exclusion(&rule2, object_set{root.at(1)});
    derived.add_rule_exclusion(&rule3, filter_mode::custom, "block");

    EXPECT_EQ(derived.size(), 3);
    EXPECT_EQ(derived.find(&rule1).mode, filter_mode::bypass);
    EXPECT_EQ(derived.find(&rule2).objects.size(), 2);
    EXPECT_EQ(derived.find(&rule3).mode, filter_mode::custom);
    EXPECT_EQ(derived.find(&rule3).action_override, "block");

    // The upstream policy is unchanged
    EXPECT_EQ(upstream.size(), 2);
    EXPECT_EQ(upstream.find(&rule1).mode, filter_mode::monitor);
    EXPECT_EQ(upstream.find(&rule2).objects.size(), 1);
    EXPECT_FALSE(upstream.contains(&rule3));
}

TEST(ExclusionPolicy, DerivedPolicyIgnoresInputsOfBypassedRule)
{
    auto rule = make_rule("1");
    auto root = object_builder_da::map({{"value", "node"}});

    exclusion_policy upstream;
    upstream.add_rule_exclusion(&rule, filter_mode::bypass, {});

    auto derived = exclusion_policy::derive(upstream);
    derived.add_input_exclusion(&rule, object_set{root.at(0)});
    EXPECT_TRUE(derived.per_rule.empty());
    EXPECT_EQ(derived.find(&rule).mode, filter_mode::bypass);
    EXPECT_TRUE(derived.find(&rule).objects.empty());
}

} // namespace
