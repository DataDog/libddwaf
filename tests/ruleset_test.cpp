// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

namespace {
std::vector<rule::ptr> test_rules()
{
    return {std::make_shared<ddwaf::rule>("id0", "name",
                std::unordered_map<std::string, std::string>{
                    {"type", "type0"}, {"category", "category0"}},
                std::vector<condition::ptr>{}, std::vector<std::string>{}),
        std::make_shared<ddwaf::rule>("id1", "name",
            std::unordered_map<std::string, std::string>{
                {"type", "type1"}, {"category", "category0"}},
            std::vector<condition::ptr>{}, std::vector<std::string>{}),
        std::make_shared<ddwaf::rule>("id2", "name",
            std::unordered_map<std::string, std::string>{
                {"type", "type1"}, {"category", "category0"}},
            std::vector<condition::ptr>{}, std::vector<std::string>{}),
        std::make_shared<ddwaf::rule>("id3", "name",
            std::unordered_map<std::string, std::string>{
                {"type", "type2"}, {"category", "category0"}},
            std::vector<condition::ptr>{}, std::vector<std::string>{}),
        std::make_shared<ddwaf::rule>("id4", "name",
            std::unordered_map<std::string, std::string>{
                {"type", "type2"}, {"category", "category1"}},
            std::vector<condition::ptr>{}, std::vector<std::string>{}),
        std::make_shared<ddwaf::rule>("id5", "name",
            std::unordered_map<std::string, std::string>{
                {"type", "type2"}, {"category", "category1"}},
            std::vector<condition::ptr>{}, std::vector<std::string>{})};
}
} // namespace

TEST(TestRuleset, Insert)
{
    ddwaf::ruleset ruleset;
    for (const auto &rule : test_rules()) { ruleset.insert_rule(rule); }

    EXPECT_EQ(ruleset.rules.size(), 6);
    EXPECT_EQ(ruleset.collections.size(), 3);
}

TEST(TestRuleset, InsertContainer)
{
    ddwaf::ruleset ruleset;
    std::unordered_map<std::string_view, rule::ptr> rules;
    for (const auto &rule : test_rules()) { rules.emplace(rule->id, rule); }
    ruleset.insert_rules(rules);

    EXPECT_EQ(ruleset.rules.size(), 6);
    EXPECT_EQ(ruleset.collections.size(), 3);
}
