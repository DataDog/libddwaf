// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

namespace {
std::vector<rule::ptr> test_rules() {
    return {
        std::make_shared<ddwaf::rule>("id0", "name", "type0", "category0",
            std::vector<condition::ptr>{}, std::vector<std::string>{}),
        std::make_shared<ddwaf::rule>("id1", "name", "type1", "category0",
            std::vector<condition::ptr>{}, std::vector<std::string>{}),
        std::make_shared<ddwaf::rule>("id2", "name", "type1", "category0",
            std::vector<condition::ptr>{}, std::vector<std::string>{}),
        std::make_shared<ddwaf::rule>("id3", "name", "type2", "category0",
            std::vector<condition::ptr>{}, std::vector<std::string>{}),
        std::make_shared<ddwaf::rule>("id4", "name", "type2", "category1",
            std::vector<condition::ptr>{}, std::vector<std::string>{}),
        std::make_shared<ddwaf::rule>("id5", "name", "type2", "category1",
            std::vector<condition::ptr>{}, std::vector<std::string>{})
    };
}
} // namespace

TEST(TestRuleset, Insert)
{
    ddwaf::ruleset ruleset;
    for (const auto &rule : test_rules()) { ruleset.insert_rule(rule); }

    EXPECT_EQ(ruleset.rules.size(), 6);
    EXPECT_EQ(ruleset.collections.size(), 3);
    EXPECT_EQ(ruleset.rules_by_type.size(), 3);
    EXPECT_EQ(ruleset.rules_by_category.size(), 2);
}

TEST(TestRuleset, ByCategory)
{
    auto rules = test_rules();
    ddwaf::ruleset ruleset;
    for (const auto &rule : rules) { ruleset.insert_rule(rule); }

    {
        auto by_category = ruleset.get_rules_by_category("category0");
        EXPECT_EQ(by_category.size(), 4);
        EXPECT_NE(by_category.find(rules[0]), by_category.end());
        EXPECT_NE(by_category.find(rules[1]), by_category.end());
        EXPECT_NE(by_category.find(rules[2]), by_category.end());
        EXPECT_NE(by_category.find(rules[3]), by_category.end());
    }

    {
        auto by_category = ruleset.get_rules_by_category("category1");
        EXPECT_EQ(by_category.size(), 2);
        EXPECT_NE(by_category.find(rules[4]), by_category.end());
        EXPECT_NE(by_category.find(rules[5]), by_category.end());
    }

    {
        auto by_category = ruleset.get_rules_by_category("category2");
        EXPECT_EQ(by_category.size(), 0);
    }
}

TEST(TestRuleset, ByType)
{
    auto rules = test_rules();
    ddwaf::ruleset ruleset;
    for (const auto &rule : rules) { ruleset.insert_rule(rule); }

    {
        auto by_type = ruleset.get_rules_by_type("type0");
        EXPECT_EQ(by_type.size(), 1);
        EXPECT_NE(by_type.find(rules[0]), by_type.end());
    }

    {
        auto by_type = ruleset.get_rules_by_type("type1");
        EXPECT_EQ(by_type.size(), 2);
        EXPECT_NE(by_type.find(rules[1]), by_type.end());
        EXPECT_NE(by_type.find(rules[2]), by_type.end());
    }

    {
        auto by_type = ruleset.get_rules_by_type("type2");
        EXPECT_EQ(by_type.size(), 3);
        EXPECT_NE(by_type.find(rules[3]), by_type.end());
        EXPECT_NE(by_type.find(rules[4]), by_type.end());
        EXPECT_NE(by_type.find(rules[5]), by_type.end());
    }

    {
        auto by_type = ruleset.get_rules_by_type("type3");
        EXPECT_EQ(by_type.size(), 0);
    }
}

/*std::make_shared<ddwaf::rule>("id0", "name", "type0", "category0",*/
/*std::make_shared<ddwaf::rule>("id1", "name", "type1", "category0",*/
/*std::make_shared<ddwaf::rule>("id2", "name", "type1", "category0",*/
/*std::make_shared<ddwaf::rule>("id3", "name", "type2", "category0",*/
/*std::make_shared<ddwaf::rule>("id4", "name", "type2", "category1",*/
/*std::make_shared<ddwaf::rule>("id5", "name", "type2", "category1",*/

TEST(TestRuleset, ByTypeAndCategory)
{
    auto rules = test_rules();
    ddwaf::ruleset ruleset;
    for (const auto &rule : rules) { ruleset.insert_rule(rule); }

    {
        auto by_tags = ruleset.get_rules_by_type_and_category("type0", "category0");
        EXPECT_EQ(by_tags.size(), 1);
        EXPECT_NE(by_tags.find(rules[0]), by_tags.end());
    }

    {
        auto by_tags = ruleset.get_rules_by_type_and_category("type1", "category0");
        EXPECT_EQ(by_tags.size(), 2);
        EXPECT_NE(by_tags.find(rules[1]), by_tags.end());
        EXPECT_NE(by_tags.find(rules[2]), by_tags.end());
    }

    {
        auto by_tags = ruleset.get_rules_by_type_and_category("type2", "category0");
        EXPECT_EQ(by_tags.size(), 1);
        EXPECT_NE(by_tags.find(rules[3]), by_tags.end());
    }

    {
        auto by_tags = ruleset.get_rules_by_type_and_category("type0", "category1");
        EXPECT_EQ(by_tags.size(), 0);
    }

    {
        auto by_tags = ruleset.get_rules_by_type_and_category("type1", "category1");
        EXPECT_EQ(by_tags.size(), 0);
    }

    {
        auto by_tags = ruleset.get_rules_by_type_and_category("type2", "category1");
        EXPECT_EQ(by_tags.size(), 2);
        EXPECT_NE(by_tags.find(rules[4]), by_tags.end());
        EXPECT_NE(by_tags.find(rules[5]), by_tags.end());
    }
}
