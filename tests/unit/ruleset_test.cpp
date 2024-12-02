// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ruleset.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;

namespace {
std::shared_ptr<core_rule> make_rule(std::string id, std::string name,
    std::unordered_map<std::string, std::string> tags, std::vector<std::string> actions,
    core_rule::source_type source = core_rule::source_type::base)
{
    return std::make_shared<core_rule>(std::move(id), std::move(name), std::move(tags),
        std::make_shared<expression>(), std::move(actions), true, source);
}

TEST(TestRuleset, InsertSingleRegularBaseRules)
{
    std::vector<std::shared_ptr<core_rule>> rules{
        make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {}),
        make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {}),
        make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {}),
        make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {}),
        make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {}),
        make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {}),
    };

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        /*        //EXPECT_EQ(ruleset.base/g_collections.size(), 3);*/
        /*//EXPECT_EQ(ruleset.base/g_priority_collections.size(), 0);*/
        /*//EXPECT_EQ(ruleset.user/g_collections.size(), 0);*/
        /*//EXPECT_EQ(ruleset.user/g_priority_collections.size(), 0);*/
    }

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        /*        //EXPECT_EQ(ruleset.base/g_collections.size(), 3);*/
        /*//EXPECT_EQ(ruleset.base/g_priority_collections.size(), 0);*/
        /*//EXPECT_EQ(ruleset.user/g_collections.size(), 0);*/
        /*//EXPECT_EQ(ruleset.user/g_priority_collections.size(), 0);*/
    }
}

TEST(TestRuleset, InsertSinglePriorityBaseRules)
{
    std::vector<std::shared_ptr<core_rule>> rules{
        make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {"block"}),
        make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {"block"}),
        make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {"block"}),
        make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {"block"}),
        make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"}),
        make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"}),
    };

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        ////EXPECT_EQ(ruleset.base/g_collections.size(), 0);
        ////EXPECT_EQ(ruleset.base/g_priority_collections.size(), 3);
        ////EXPECT_EQ(ruleset.user/g_collections.size(), 0);
        ////EXPECT_EQ(ruleset.user/g_priority_collections.size(), 0);
    }

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        ////EXPECT_EQ(ruleset.base/g_collections.size(), 0);
        ////EXPECT_EQ(ruleset.base/g_priority_collections.size(), 3);
        ////EXPECT_EQ(ruleset.user/g_collections.size(), 0);
        ////EXPECT_EQ(ruleset.user/g_priority_collections.size(), 0);
    }
}

TEST(TestRuleset, InsertSingleMixedBaseRules)
{
    std::vector<std::shared_ptr<core_rule>> rules{
        make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {}),
        make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {}),
        make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {"block"}),
        make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {}),
        make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"}),
        make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"}),
    };

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 2);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 0);
    }

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 2);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 0);
    }
}

TEST(TestRuleset, InsertSingleRegularUserRules)
{
    std::vector<std::shared_ptr<core_rule>> rules{
        make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {},
            core_rule::source_type::user),
        make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {},
            core_rule::source_type::user),
    };

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 0);
    }

    {
        ddwaf::ruleset ruleset;

        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 0);
    }
}

TEST(TestRuleset, InsertSinglePriorityUserRules)
{
    std::vector<std::shared_ptr<core_rule>> rules{
        make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"},
            core_rule::source_type::user),
    };
    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 3);
    }

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 3);
    }
}

TEST(TestRuleset, InsertSingleMixedUserRules)
{
    std::vector<std::shared_ptr<core_rule>> rules{
        make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"},
            core_rule::source_type::user),
    };

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 2);
    }

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 2);
    }
}

TEST(TestRuleset, InsertSingleRegularMixedRules)
{
    std::vector<std::shared_ptr<core_rule>> rules{
        make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {},
            core_rule::source_type::base),
        make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {},
            core_rule::source_type::base),
        make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {},
            core_rule::source_type::base),
        make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {},
            core_rule::source_type::user),
    };

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 2);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 0);
    }

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 2);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 0);
    }
}

TEST(TestRuleset, InsertSinglePriorityMixedRules)
{
    std::vector<std::shared_ptr<core_rule>> rules{
        make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {"block"},
            core_rule::source_type::base),
        make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {"block"},
            core_rule::source_type::base),
        make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"},
            core_rule::source_type::base),
        make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"},
            core_rule::source_type::user),
    };
    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 3);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 2);
    }

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 6);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 3);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 0);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 2);
    }
}

TEST(TestRuleset, InsertSingleMixedMixedRules)
{
    std::vector<std::shared_ptr<core_rule>> rules{
        make_rule("id0", "name", {{"type", "type0"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id1", "name", {{"type", "type1"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id2", "name", {{"type", "type1"}, {"category", "category0"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id3", "name", {{"type", "type2"}, {"category", "category0"}}, {},
            core_rule::source_type::user),
        make_rule("id4", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id5", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"},
            core_rule::source_type::user),
        make_rule("id6", "name", {{"type", "type0"}, {"category", "category0"}}, {}),
        make_rule("id7", "name", {{"type", "type1"}, {"category", "category0"}}, {}),
        make_rule("id8", "name", {{"type", "type1"}, {"category", "category0"}}, {"block"}),
        make_rule("id9", "name", {{"type", "type2"}, {"category", "category0"}}, {}),
        make_rule("id10", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"}),
        make_rule("id11", "name", {{"type", "type2"}, {"category", "category1"}}, {"block"}),
    };

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 12);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 2);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 2);
    }

    {
        ddwaf::ruleset ruleset;
        ruleset.insert_rules(rules, {});

        EXPECT_EQ(ruleset.rules.size(), 12);
        // EXPECT_EQ(ruleset.base/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.base/g_priority_collections.size(), 2);
        // EXPECT_EQ(ruleset.user/g_collections.size(), 3);
        // EXPECT_EQ(ruleset.user/g_priority_collections.size(), 2);
    }
}

} // namespace
