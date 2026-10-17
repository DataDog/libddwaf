// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <array>

#include "mkmap.hpp"
#include "ruleset.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

using rule_tag_map = ddwaf::multi_key_map<std::string_view, core_rule *>;

namespace {

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

    std::vector<std::shared_ptr<core_rule>> rules;
    for (const auto &spec : specs) {
        std::unordered_map<std::string, std::string> tags = spec.tags;
        tags.emplace("type", spec.type);
        tags.emplace("category", spec.category);

        auto rule_ptr = std::make_shared<core_rule>(
            std::string(spec.id), "name", decltype(tags)(tags), std::make_shared<expression>());
        rules.emplace_back(rule_ptr);
        ruledb.insert(rule_ptr->get_tags(), rule_ptr.get());
    }

    using sv_pair = std::pair<std::string_view, std::string_view>;
    {
        auto rules = ruledb.find(sv_pair{"type"sv, "type0"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(sv_pair{"category", "category0"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(sv_pair{"key"sv, "value0"sv});
        EXPECT_EQ(rules.size(), 4);
    }

    using s_pair = std::pair<std::string, std::string>;
    {
        auto rules = ruledb.find(s_pair{"type"sv, "type1"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(s_pair{"category", "category1"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(s_pair{"key"sv, "value1"sv});
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

    std::vector<std::shared_ptr<core_rule>> rules;
    for (const auto &spec : specs) {
        std::unordered_map<std::string, std::string> tags = spec.tags;
        tags.emplace("type", spec.type);
        tags.emplace("category", spec.category);

        auto rule_ptr = std::make_shared<core_rule>(
            std::string(spec.id), "name", decltype(tags)(tags), std::make_shared<expression>());
        rules.emplace_back(rule_ptr);
        ruledb.insert(rule_ptr->get_tags(), rule_ptr.get());
    }

    using sv_pair_vec = std::vector<std::pair<std::string, std::string>>;
    {
        auto rules = ruledb.multifind(sv_pair_vec{{"type", "type0"}});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.multifind(sv_pair_vec{{"category", "category0"}});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.multifind(sv_pair_vec{{"type", "type0"}, {"category", "category0"}});
        EXPECT_EQ(rules.size(), 2);
    }

    {
        auto rules = ruledb.multifind(sv_pair_vec{{"key", "value0"}});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.multifind(sv_pair_vec{{"type", "type0"}, {"key", "value0"}});
        EXPECT_EQ(rules.size(), 2);
    }

    {
        auto rules = ruledb.multifind(sv_pair_vec{{"category", "category0"}, {"key", "value0"}});
        EXPECT_EQ(rules.size(), 2);
    }

    {
        auto rules = ruledb.multifind(
            sv_pair_vec{{"type", "type0"}, {"category", "category0"}, {"key", "value0"}});
        EXPECT_EQ(rules.size(), 1);
    }
}

TEST(TestMultiKeyMap, Erase)
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

    std::vector<std::shared_ptr<core_rule>> rules;
    for (const auto &spec : specs) {
        std::unordered_map<std::string, std::string> tags = spec.tags;
        tags.emplace("type", spec.type);
        tags.emplace("category", spec.category);

        auto rule_ptr = std::make_shared<core_rule>(
            std::string(spec.id), "name", decltype(tags)(tags), std::make_shared<expression>());
        rules.emplace_back(rule_ptr);
        ruledb.insert(rule_ptr->get_tags(), rule_ptr.get());
    }

    using sv_pair = std::pair<std::string_view, std::string_view>;
    {
        auto rules = ruledb.find(sv_pair{"type"sv, "type0"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(sv_pair{"category", "category0"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(sv_pair{"key"sv, "value0"sv});
        EXPECT_EQ(rules.size(), 4);
    }

    using s_pair = std::pair<std::string, std::string>;
    {
        auto rules = ruledb.find(s_pair{"type"sv, "type1"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(s_pair{"category", "category1"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(s_pair{"key"sv, "value1"sv});
        EXPECT_EQ(rules.size(), 4);
    }

    ruledb.erase(rules[3]->get_tags(), rules[3].get());
    {
        auto rules = ruledb.find(sv_pair{"type"sv, "type0"});
        EXPECT_EQ(rules.size(), 3);
    }

    {
        auto rules = ruledb.find(sv_pair{"category", "category0"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(sv_pair{"key"sv, "value0"sv});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(sv_pair{"type"sv, "type1"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(sv_pair{"category", "category1"});
        EXPECT_EQ(rules.size(), 3);
    }

    {
        auto rules = ruledb.find(sv_pair{"key"sv, "value1"sv});
        EXPECT_EQ(rules.size(), 3);
    }

    ruledb.erase(rules[0]->get_tags(), rules[0].get());
    {
        auto rules = ruledb.find(sv_pair{"type"sv, "type0"});
        EXPECT_EQ(rules.size(), 2);
    }

    {
        auto rules = ruledb.find(sv_pair{"category", "category0"});
        EXPECT_EQ(rules.size(), 3);
    }

    {
        auto rules = ruledb.find(sv_pair{"key"sv, "value0"sv});
        EXPECT_EQ(rules.size(), 3);
    }

    {
        auto rules = ruledb.find(sv_pair{"type"sv, "type1"});
        EXPECT_EQ(rules.size(), 4);
    }

    {
        auto rules = ruledb.find(sv_pair{"category", "category1"});
        EXPECT_EQ(rules.size(), 3);
    }

    {
        auto rules = ruledb.find(sv_pair{"key"sv, "value1"sv});
        EXPECT_EQ(rules.size(), 3);
    }

    ruledb.erase(rules[7]->get_tags(), rules[7].get());
    {
        auto rules = ruledb.find(sv_pair{"type"sv, "type0"});
        EXPECT_EQ(rules.size(), 2);
    }

    {
        auto rules = ruledb.find(sv_pair{"category", "category0"});
        EXPECT_EQ(rules.size(), 3);
    }

    {
        auto rules = ruledb.find(sv_pair{"key"sv, "value0"sv});
        EXPECT_EQ(rules.size(), 3);
    }

    {
        auto rules = ruledb.find(sv_pair{"type"sv, "type1"});
        EXPECT_EQ(rules.size(), 3);
    }

    {
        auto rules = ruledb.find(sv_pair{"category", "category1"});
        EXPECT_EQ(rules.size(), 2);
    }

    {
        auto rules = ruledb.find(sv_pair{"key"sv, "value1"sv});
        EXPECT_EQ(rules.size(), 2);
    }
}

TEST(TestMultiKeyMap, ResultsAreSortedAndUnique)
{
    multi_key_map<std::string, int *> map;
    std::array<int, 6> storage{};
    using tags_type = std::unordered_map<std::string, std::string>;

    // Out of order and repeated insertions
    for (unsigned i : {4U, 0U, 5U, 2U, 2U, 1U, 3U, 0U}) {
        tags_type tags{{"type", "t"}, {"parity", (i % 2) == 0 ? "even" : "odd"}};
        if (i >= 3) {
            tags.emplace("high", "yes");
        }
        map.insert(tags, &storage[i]);
    }

    auto is_sorted = [](const auto &v) {
        return std::is_sorted(v.begin(), v.end(), std::less<int *>{}) &&
               std::adjacent_find(v.begin(), v.end()) == v.end();
    };

    using pair_vec = std::vector<std::pair<std::string, std::string>>;
    {
        auto items = map.multifind(pair_vec{{"type", "t"}});
        EXPECT_EQ(items.size(), 6);
        EXPECT_TRUE(is_sorted(items));
    }
    {
        auto items = map.multifind(pair_vec{{"type", "t"}, {"parity", "even"}});
        EXPECT_EQ(items, (std::vector<int *>{&storage[0], &storage[2], &storage[4]}));
    }
    {
        auto items = map.multifind(pair_vec{{"type", "t"}, {"parity", "odd"}, {"high", "yes"}});
        EXPECT_EQ(items, (std::vector<int *>{&storage[3], &storage[5]}));
    }
    {
        auto items = map.multifind(pair_vec{{"type", "t"}, {"parity", "odd"}, {"high", "no"}});
        EXPECT_TRUE(items.empty());
    }

    map.erase(tags_type{{"type", "t"}}, &storage[2]);
    map.erase(tags_type{{"type", "t"}}, &storage[2]);
    {
        auto items = map.multifind(pair_vec{{"type", "t"}});
        EXPECT_EQ(items, (std::vector<int *>{
                             &storage[0], &storage[1], &storage[3], &storage[4], &storage[5]}));
    }
}

} // namespace
