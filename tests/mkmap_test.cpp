// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

TEST(TestMultiKeyMap, Find)
{
    rule_tag_map ruledb;

    struct rule_spec {
        std::string id;
        std::string type;
        std::string category;
        std::unordered_map<std::string, std::string> tags;
    };

    std::vector<rule_spec> specs{{"id0", "type0", "category0", {{"key", "value0"}}},
        {"id1", "type0", "category0", {{"key", "value1"}}},
        {"id2", "type0", "category1", {{"key", "value0"}}},
        {"id3", "type0", "category1", {{"key", "value1"}}},
        {"id4", "type1", "category0", {{"key", "value0"}}},
        {"id5", "type1", "category0", {{"key", "value1"}}},
        {"id6", "type1", "category1", {{"key", "value0"}}},
        {"id7", "type1", "category1", {{"key", "value1"}}}};

    for (const auto &spec : specs) {
        std::unordered_map<std::string, std::string> tags = spec.tags;
        tags.emplace("type", spec.type);
        tags.emplace("category", spec.category);

        auto rule_ptr = std::make_shared<ddwaf::rule>(
            std::string(spec.id), "name", decltype(tags)(tags), std::vector<condition::ptr>{});
        ruledb.insert(rule_ptr->tags, rule_ptr);
    }

    {
        auto rules = ruledb.find({"type", "type0"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find({"category", "category0"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find({"key", "value0"});
        EXPECT_EQ(rules.size(), 4);
    }
}

TEST(TestMultiKeyMap, Multifind)
{
    rule_tag_map ruledb;

    struct rule_spec {
        std::string id;
        std::string type;
        std::string category;
        std::unordered_map<std::string, std::string> tags;
    };

    std::vector<rule_spec> specs{{"id0", "type0", "category0", {{"key", "value0"}}},
        {"id1", "type0", "category0", {{"key", "value1"}}},
        {"id2", "type0", "category1", {{"key", "value0"}}},
        {"id3", "type0", "category1", {{"key", "value1"}}},
        {"id4", "type1", "category0", {{"key", "value0"}}},
        {"id5", "type1", "category0", {{"key", "value1"}}},
        {"id6", "type1", "category1", {{"key", "value0"}}},
        {"id7", "type1", "category1", {{"key", "value1"}}}};

    for (const auto &spec : specs) {
        std::unordered_map<std::string, std::string> tags = spec.tags;
        tags.emplace("type", spec.type);
        tags.emplace("category", spec.category);

        auto rule_ptr = std::make_shared<ddwaf::rule>(
            std::string(spec.id), "name", decltype(tags)(tags), std::vector<condition::ptr>{});
        ruledb.insert(rule_ptr->tags, rule_ptr);
    }

    {
        auto rules = ruledb.multifind({{"type", "type0"}});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.multifind({{"category", "category0"}});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.multifind({{"type", "type0"}, {"category", "category0"}});
        EXPECT_EQ(rules.size(), 2);
    }

    {
        auto rules = ruledb.multifind({{"key", "value0"}});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.multifind({{"type", "type0"}, {"key", "value0"}});
        EXPECT_EQ(rules.size(), 2);
    }

    {
        auto rules = ruledb.multifind({{"category", "category0"}, {"key", "value0"}});
        EXPECT_EQ(rules.size(), 2);
    }

    {
        auto rules =
            ruledb.multifind({{"type", "type0"}, {"category", "category0"}, {"key", "value0"}});
        EXPECT_EQ(rules.size(), 1);
    }
}
