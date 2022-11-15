// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

namespace ddwaf::test {
class context : public ddwaf::context {
public:
    context(ddwaf::ruleset &ruleset, const ddwaf::config &config) : ddwaf::context(ruleset, config)
    {}

    bool insert(const ddwaf_object &object) { return store_.insert(object); }
};

} // namespace ddwaf::test

TEST(TestContext, MatchTimeout)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", "type", "category",
        std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

    ddwaf::ruleset ruleset;
    ruleset.rules.emplace("id", rule);
    ruleset.collections["type"].emplace_back(rule);
    ruleset.manifest = mb.build_manifest();

    ddwaf::timer deadline{0s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    EXPECT_THROW(ctx.match({}, deadline), ddwaf::timeout_exception);
}

TEST(TestContext, NoMatch)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", "type", "category",
        std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

    ddwaf::ruleset ruleset;
    ruleset.rules.emplace("id", rule);
    ruleset.collections["type"].emplace_back(rule);
    ruleset.manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));
    ctx.insert(root);

    auto events = ctx.match({}, deadline);
    EXPECT_EQ(events.size(), 0);
}

TEST(TestContext, Match)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", "type", "category",
        std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

    ddwaf::ruleset ruleset;
    ruleset.rules.emplace("id", rule);
    ruleset.collections["type"].emplace_back(rule);
    ruleset.manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    auto events = ctx.match({}, deadline);
    EXPECT_EQ(events.size(), 1);
}

TEST(TestContext, MatchMultipleRulesInCollectionSingleRun)
{
    ddwaf::ruleset ruleset;
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", "type", "category1",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id1", rule);
        ruleset.collections["type"].emplace_back(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", "type", "category2",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id2", rule);
        ruleset.collections["type"].emplace_back(rule);
    }

    ruleset.manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.match({}, deadline);
    EXPECT_EQ(events.size(), 1);

    auto &event = events[0];
    EXPECT_STREQ(event.id.data(), "id1");
    EXPECT_STREQ(event.name.data(), "name1");
    EXPECT_STREQ(event.type.data(), "type");
    EXPECT_STREQ(event.category.data(), "category1");
    std::vector<std::string_view> expected_actions{"update", "block", "passlist"};
    EXPECT_EQ(event.actions, expected_actions);
    EXPECT_EQ(event.matches.size(), 1);

    auto &match = event.matches[0];
    EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
    EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
    EXPECT_STREQ(match.operator_name.data(), "ip_match");
    EXPECT_STREQ(match.operator_value.data(), "");
    EXPECT_STREQ(match.source.data(), "http.client_ip");
    EXPECT_TRUE(match.key_path.empty());
}

TEST(TestContext, MatchMultipleRulesInCollectionDoubleRun)
{
    ddwaf::ruleset ruleset;
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", "type", "category1",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id1", rule);
        ruleset.collections["type"].emplace_back(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", "type", "category2",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id2", rule);
        ruleset.collections["type"].emplace_back(rule);
    }

    ruleset.manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.match({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STREQ(event.id.data(), "id1");
        EXPECT_STREQ(event.name.data(), "name1");
        EXPECT_STREQ(event.type.data(), "type");
        EXPECT_STREQ(event.category.data(), "category1");
        std::vector<std::string_view> expected_actions{"update", "block", "passlist"};
        EXPECT_EQ(event.actions, expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.operator_name.data(), "ip_match");
        EXPECT_STREQ(match.operator_value.data(), "");
        EXPECT_STREQ(match.source.data(), "http.client_ip");
        EXPECT_TRUE(match.key_path.empty());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.match({}, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, MatchMultipleCollectionsSingleRun)
{
    ddwaf::ruleset ruleset;
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", "type1", "category1",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id1", rule);
        ruleset.collections["type1"].emplace_back(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", "type2", "category2",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id2", rule);
        ruleset.collections["type2"].emplace_back(rule);
    }

    ruleset.manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.match({}, deadline);
    EXPECT_EQ(events.size(), 2);
}

TEST(TestContext, MatchMultipleCollectionsDoubleRun)
{
    ddwaf::ruleset ruleset;
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", "type1", "category1",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id1", rule);
        ruleset.collections["type1"].emplace_back(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", "type2", "category2",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id2", rule);
        ruleset.collections["type2"].emplace_back(rule);
    }

    ruleset.manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.match({}, deadline);
        EXPECT_EQ(events.size(), 1);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.match({}, deadline);
        EXPECT_EQ(events.size(), 1);
    }
}

TEST(TestContext, FilterWithCondition)
{
    ddwaf::ruleset ruleset;
    ddwaf::manifest_builder mb;

    // Generate rule
    ddwaf::rule::ptr rule;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        rule = std::make_shared<ddwaf::rule>("id", "name", "type", "category",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id", rule);
        ruleset.collections["type"].emplace_back(rule);
    }

    // Generate filter
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<ddwaf::exclusion_filter>(
            std::move(conditions), std::set<ddwaf::rule::ptr>{rule});
        ruleset.filters.emplace_back(filter);
    }

    ruleset.manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    auto rules_to_exclude = ctx.filter(deadline);
    EXPECT_EQ(rules_to_exclude.size(), 1);
    EXPECT_NE(rules_to_exclude.find(rule), rules_to_exclude.end());

    auto events = ctx.match(rules_to_exclude, deadline);
    EXPECT_EQ(events.size(), 0);
}

TEST(TestContext, FilterTimeout)
{
    ddwaf::ruleset ruleset;
    ddwaf::manifest_builder mb;

    // Generate rule
    ddwaf::rule::ptr rule;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        rule = std::make_shared<ddwaf::rule>("id", "name", "type", "category",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id", rule);
        ruleset.collections["type"].emplace_back(rule);
    }

    // Generate filter
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<ddwaf::exclusion_filter>(
            std::move(conditions), std::set<ddwaf::rule::ptr>{rule});
        ruleset.filters.emplace_back(filter);
    }

    ruleset.manifest = mb.build_manifest();

    ddwaf::timer deadline{0s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    EXPECT_THROW(ctx.filter(deadline), ddwaf::timeout_exception);
}

TEST(TestContext, NoFilterWithCondition)
{
    ddwaf::ruleset ruleset;
    ddwaf::manifest_builder mb;

    // Generate rule
    ddwaf::rule::ptr rule;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        rule = std::make_shared<ddwaf::rule>("id", "name", "type", "category",
            std::move(conditions), std::vector<std::string>{"update", "block", "passlist"});

        ruleset.rules.emplace("id", rule);
        ruleset.collections["type"].emplace_back(rule);
    }

    // Generate filter
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<ddwaf::exclusion_filter>(
            std::move(conditions), std::set<ddwaf::rule::ptr>{rule});
        ruleset.filters.emplace_back(filter);
    }

    ruleset.manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));
    ctx.insert(root);

    auto rules_to_exclude = ctx.filter(deadline);
    EXPECT_TRUE(rules_to_exclude.empty());

    auto events = ctx.match(rules_to_exclude, deadline);
    EXPECT_EQ(events.size(), 1);
}

TEST(TestContext, MultipleFiltersNonOverlappingRules)
{
    ddwaf::ruleset ruleset;

    // Generate rule
    constexpr unsigned num_rules = 9;
    std::vector<ddwaf::rule::ptr> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);
        rules.emplace_back(std::make_shared<ddwaf::rule>(std::string(id), "name", "type",
            "category", std::vector<ddwaf::condition::ptr>{}, std::vector<std::string>{}));

        ruleset.rules.emplace(id, rules[i]);
        ruleset.collections["type"].emplace_back(rules[i]);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    {
        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 0);
    }

    ruleset.filters.emplace_back(std::make_shared<ddwaf::exclusion_filter>(
        std::vector<condition::ptr>{}, std::set<ddwaf::rule::ptr>{rules[0], rules[1], rules[2]}));

    {
        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 3);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
    }

    ruleset.filters.emplace_back(std::make_shared<ddwaf::exclusion_filter>(
        std::vector<condition::ptr>{}, std::set<ddwaf::rule::ptr>{rules[3], rules[4], rules[5]}));

    {
        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 6);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[5]), rules_to_exclude.end());
    }

    ruleset.filters.emplace_back(std::make_shared<ddwaf::exclusion_filter>(
        std::vector<condition::ptr>{}, std::set<ddwaf::rule::ptr>{rules[6], rules[7], rules[8]}));

    {
        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[5]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[6]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[7]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[8]), rules_to_exclude.end());
    }
}

TEST(TestContext, MultipleFiltersOverlappingRules)
{
    ddwaf::ruleset ruleset;

    // Generate rule
    constexpr unsigned num_rules = 9;
    std::vector<ddwaf::rule::ptr> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);
        rules.emplace_back(std::make_shared<ddwaf::rule>(std::string(id), "name", "type",
            "category", std::vector<ddwaf::condition::ptr>{}, std::vector<std::string>{}));

        ruleset.rules.emplace(id, rules[i]);
        ruleset.collections["type"].emplace_back(rules[i]);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    {
        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 0);
    }

    ruleset.filters.emplace_back(
        std::make_shared<ddwaf::exclusion_filter>(std::vector<condition::ptr>{},
            std::set<ddwaf::rule::ptr>{rules[0], rules[1], rules[2], rules[3]}));

    {
        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 4);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
    }

    ruleset.filters.emplace_back(std::make_shared<ddwaf::exclusion_filter>(
        std::vector<condition::ptr>{}, std::set<ddwaf::rule::ptr>{rules[2], rules[3], rules[4]}));

    {
        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 5);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
    }

    ruleset.filters.emplace_back(std::make_shared<ddwaf::exclusion_filter>(
        std::vector<condition::ptr>{}, std::set<ddwaf::rule::ptr>{rules[0], rules[5], rules[6]}));

    {
        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 7);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[5]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[6]), rules_to_exclude.end());
    }

    ruleset.filters.emplace_back(std::make_shared<ddwaf::exclusion_filter>(
        std::vector<condition::ptr>{}, std::set<ddwaf::rule::ptr>{rules[7], rules[8], rules[6]}));
    {
        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[5]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[6]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[7]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[8]), rules_to_exclude.end());
    }
    ruleset.filters.emplace_back(
        std::make_shared<ddwaf::exclusion_filter>(std::vector<condition::ptr>{},
            std::set<ddwaf::rule::ptr>{rules[0], rules[1], rules[2], rules[3], rules[4], rules[5],
                rules[6], rules[7], rules[8]}));
    {
        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[5]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[6]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[7]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[8]), rules_to_exclude.end());
    }
}

TEST(TestContext, MultipleFiltersNonOverlappingRulesWithConditions)
{
    ddwaf::ruleset ruleset;
    ddwaf::manifest_builder mb;

    // Generate rule
    constexpr unsigned num_rules = 10;
    std::vector<ddwaf::rule::ptr> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);
        rules.emplace_back(std::make_shared<ddwaf::rule>(std::string(id), "name", "type",
            "category", std::vector<ddwaf::condition::ptr>{}, std::vector<std::string>{}));

        ruleset.rules.emplace(id, rules[i]);
        ruleset.collections["type"].emplace_back(rules[i]);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<ddwaf::exclusion_filter>(std::move(conditions),
            std::set<ddwaf::rule::ptr>{rules[0], rules[1], rules[2], rules[3], rules[4]});
        ruleset.filters.emplace_back(filter);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<ddwaf::exclusion_filter>(std::move(conditions),
            std::set<ddwaf::rule::ptr>{rules[5], rules[6], rules[7], rules[8], rules[9]});
        ruleset.filters.emplace_back(filter);
    }

    ruleset.manifest = mb.build_manifest();

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 5);
        EXPECT_NE(rules_to_exclude.find(rules[5]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[6]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[7]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[8]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[9]), rules_to_exclude.end());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 10);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[5]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[6]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[7]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[8]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[9]), rules_to_exclude.end());
    }
}

TEST(TestContext, MultipleFiltersOverlappingRulesWithConditions)
{
    ddwaf::ruleset ruleset;
    ddwaf::manifest_builder mb;

    // Generate rule
    constexpr unsigned num_rules = 10;
    std::vector<ddwaf::rule::ptr> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);
        rules.emplace_back(std::make_shared<ddwaf::rule>(std::string(id), "name", "type",
            "category", std::vector<ddwaf::condition::ptr>{}, std::vector<std::string>{}));

        ruleset.rules.emplace(id, rules[i]);
        ruleset.collections["type"].emplace_back(rules[i]);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset, ddwaf::config());

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<ddwaf::exclusion_filter>(
            std::move(conditions), std::set<ddwaf::rule::ptr>{rules[0], rules[1], rules[2],
                                       rules[3], rules[4], rules[5], rules[6]});
        ruleset.filters.emplace_back(filter);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<ddwaf::exclusion_filter>(
            std::move(conditions), std::set<ddwaf::rule::ptr>{rules[3], rules[4], rules[5],
                                       rules[6], rules[7], rules[8], rules[9]});
        ruleset.filters.emplace_back(filter);
    }

    ruleset.manifest = mb.build_manifest();

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 7);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[5]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[6]), rules_to_exclude.end());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.filter(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 10);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[5]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[6]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[7]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[8]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[9]), rules_to_exclude.end());
    }
}
