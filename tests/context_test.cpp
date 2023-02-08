// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;
using namespace ddwaf::exclusion;

namespace ddwaf::test {
class context : public ddwaf::context {
public:
    context(std::shared_ptr<ddwaf::ruleset> ruleset) : ddwaf::context(ruleset) {}

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

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>(
        "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{0s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    EXPECT_THROW(ctx.match({}, {}, deadline), ddwaf::timeout_exception);
}

TEST(TestContext, NoMatch)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>(
        "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));
    ctx.insert(root);

    auto events = ctx.match({}, {}, deadline);
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

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>(
        "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    auto events = ctx.match({}, {}, deadline);
    EXPECT_EQ(events.size(), 1);
}

TEST(TestContext, MatchMultipleRulesInCollectionSingleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.match({}, {}, deadline);
    EXPECT_EQ(events.size(), 1);

    auto &event = events[0];
    EXPECT_STREQ(event.id.data(), "id1");
    EXPECT_STREQ(event.name.data(), "name1");
    EXPECT_STREQ(event.type.data(), "type");
    EXPECT_STREQ(event.category.data(), "category1");
    std::vector<std::string_view> expected_actions{};
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

TEST(TestContext, MatchMultipleRulesWithPrioritySingleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        // This rule has actions, so it'll be have priority
        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    ruleset->manifest = mb.build_manifest();

    {
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        ddwaf::timer deadline{2s};
        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto event = events[0];
        EXPECT_STREQ(event.id.data(), "id2");
        EXPECT_EQ(event.actions.size(), 1);
        EXPECT_STREQ(event.actions[0].data(), "block");
    }

    {
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        ddwaf::timer deadline{2s};
        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto event = events[0];
        EXPECT_STREQ(event.id.data(), "id2");
        EXPECT_EQ(event.actions.size(), 1);
        EXPECT_STREQ(event.actions[0].data(), "block");
    }
}

TEST(TestContext, MatchMultipleRulesInCollectionDoubleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STREQ(event.id.data(), "id1");
        EXPECT_STREQ(event.name.data(), "name1");
        EXPECT_STREQ(event.type.data(), "type");
        EXPECT_STREQ(event.category.data(), "category1");
        std::vector<std::string_view> expected_actions{};
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

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, MatchMultipleRulesWithPriorityDoubleRunPriorityLast)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STREQ(event.id.data(), "id1");
        EXPECT_STREQ(event.name.data(), "name1");
        EXPECT_STREQ(event.type.data(), "type");
        EXPECT_STREQ(event.category.data(), "category1");
        std::vector<std::string_view> expected_actions{};
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
        // An existing match in a collection will not inhibit a match in a
        // priority collection.
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_EQ(events.size(), 1);
        EXPECT_STREQ(event.id.data(), "id2");
        EXPECT_STREQ(event.name.data(), "name2");
        EXPECT_STREQ(event.type.data(), "type");
        EXPECT_STREQ(event.category.data(), "category2");
        std::vector<std::string_view> expected_actions{"block"};
        EXPECT_EQ(event.actions, expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.resolved.c_str(), "admin");
        EXPECT_STREQ(match.matched.c_str(), "admin");
        EXPECT_STREQ(match.operator_name.data(), "exact_match");
        EXPECT_STREQ(match.operator_value.data(), "");
        EXPECT_STREQ(match.source.data(), "usr.id");
        EXPECT_TRUE(match.key_path.empty());
    }
}

TEST(TestContext, MatchMultipleRulesWithPriorityDoubleRunPriorityFirst)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STREQ(event.id.data(), "id1");
        EXPECT_STREQ(event.name.data(), "name1");
        EXPECT_STREQ(event.type.data(), "type");
        EXPECT_STREQ(event.category.data(), "category1");
        std::vector<std::string_view> expected_actions{"block"};
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
        // An existing match in a collection will not inhibit a match in a
        // priority collection.
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, MatchMultipleRulesWithPriorityUntilAllActionsMet)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags),
            std::move(conditions), std::vector<std::string>{"redirect"});

        ruleset->insert_rule(rule);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STREQ(event.id.data(), "id1");
        EXPECT_STREQ(event.name.data(), "name1");
        EXPECT_STREQ(event.type.data(), "type");
        EXPECT_STREQ(event.category.data(), "category1");
        std::vector<std::string_view> expected_actions{"block"};
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
        // An existing match in a collection will not inhibit a match in a
        // priority collection.
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_EQ(events.size(), 1);
        EXPECT_STREQ(event.id.data(), "id2");
        EXPECT_STREQ(event.name.data(), "name2");
        EXPECT_STREQ(event.type.data(), "type");
        EXPECT_STREQ(event.category.data(), "category2");
        std::vector<std::string_view> expected_actions{"redirect"};
        EXPECT_EQ(event.actions, expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.resolved.c_str(), "admin");
        EXPECT_STREQ(match.matched.c_str(), "admin");
        EXPECT_STREQ(match.operator_name.data(), "exact_match");
        EXPECT_STREQ(match.operator_value.data(), "");
        EXPECT_STREQ(match.source.data(), "usr.id");
        EXPECT_TRUE(match.key_path.empty());
    }
}

TEST(TestContext, MatchMultipleCollectionsSingleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.match({}, {}, deadline);
    EXPECT_EQ(events.size(), 2);
}

TEST(TestContext, MatchMultiplePriorityCollectionsSingleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags),
            std::move(conditions), std::vector<std::string>{"redirect"});

        ruleset->insert_rule(rule);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.match({}, {}, deadline);
    EXPECT_EQ(events.size(), 2);
}

TEST(TestContext, MatchMultipleCollectionsDoubleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);
    }
}

TEST(TestContext, MatchMultiplePriorityCollectionsDoubleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags),
            std::move(conditions), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags),
            std::move(conditions), std::vector<std::string>{"redirect"});

        ruleset->insert_rule(rule);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.match({}, {}, deadline);
        EXPECT_EQ(events.size(), 1);
    }
}

TEST(TestContext, RuleFilterWithCondition)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;

    // Generate rule
    ddwaf::rule::ptr rule;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<ddwaf::rule>(
            "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<rule_filter>(
            "1", std::move(conditions), std::set<ddwaf::rule::ptr>{rule});
        ruleset->rule_filters.emplace(filter->get_id(), filter);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    auto rules_to_exclude = ctx.filter_rules(deadline);
    EXPECT_EQ(rules_to_exclude.size(), 1);
    EXPECT_NE(rules_to_exclude.find(rule), rules_to_exclude.end());

    auto events = ctx.match(rules_to_exclude, {}, deadline);
    EXPECT_EQ(events.size(), 0);
}

TEST(TestContext, RuleFilterTimeout)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;

    // Generate rule
    ddwaf::rule::ptr rule;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<ddwaf::rule>(
            "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<rule_filter>(
            "1", std::move(conditions), std::set<ddwaf::rule::ptr>{rule});
        ruleset->rule_filters.emplace(filter->get_id(), filter);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{0s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    EXPECT_THROW(ctx.filter_rules(deadline), ddwaf::timeout_exception);
}

TEST(TestContext, NoRuleFilterWithCondition)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;

    // Generate rule
    ddwaf::rule::ptr rule;
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<ddwaf::rule>(
            "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<rule_filter>(
            "1", std::move(conditions), std::set<ddwaf::rule::ptr>{rule});
        ruleset->rule_filters.emplace(filter->get_id(), filter);
    }

    ruleset->manifest = mb.build_manifest();

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));
    ctx.insert(root);

    auto rules_to_exclude = ctx.filter_rules(deadline);
    EXPECT_TRUE(rules_to_exclude.empty());

    auto events = ctx.match(rules_to_exclude, {}, deadline);
    EXPECT_EQ(events.size(), 1);
}

TEST(TestContext, MultipleRuleFiltersNonOverlappingRules)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    constexpr unsigned num_rules = 9;
    std::vector<ddwaf::rule::ptr> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<ddwaf::rule>("id" + std::to_string(i), "name",
            std::move(tags), std::vector<ddwaf::condition::ptr>{}, std::vector<std::string>{}));

        ruleset->insert_rule(rules.back());
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        auto rules_to_exclude = ctx.filter_rules(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 0);
    }

    {
        auto filter = std::make_shared<rule_filter>("1", std::vector<condition::ptr>{},
            std::set<ddwaf::rule::ptr>{rules[0], rules[1], rules[2]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);

        auto rules_to_exclude = ctx.filter_rules(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 3);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
    }

    {
        auto filter = std::make_shared<rule_filter>("2", std::vector<condition::ptr>{},
            std::set<ddwaf::rule::ptr>{rules[3], rules[4], rules[5]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);

        auto rules_to_exclude = ctx.filter_rules(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 6);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[5]), rules_to_exclude.end());
    }

    {
        auto filter = std::make_shared<rule_filter>("3", std::vector<condition::ptr>{},
            std::set<ddwaf::rule::ptr>{rules[6], rules[7], rules[8]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);

        auto rules_to_exclude = ctx.filter_rules(deadline);
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

TEST(TestContext, MultipleRuleFiltersOverlappingRules)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    constexpr unsigned num_rules = 9;
    std::vector<ddwaf::rule::ptr> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<ddwaf::rule>(std::string(id), "name", std::move(tags),
            std::vector<ddwaf::condition::ptr>{}, std::vector<std::string>{}));

        ruleset->insert_rule(rules.back());
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        auto rules_to_exclude = ctx.filter_rules(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 0);
    }

    {
        auto filter = std::make_shared<rule_filter>("1", std::vector<condition::ptr>{},
            std::set<ddwaf::rule::ptr>{rules[0], rules[1], rules[2], rules[3]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);

        auto rules_to_exclude = ctx.filter_rules(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 4);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
    }

    {
        auto filter = std::make_shared<rule_filter>("2", std::vector<condition::ptr>{},
            std::set<ddwaf::rule::ptr>{rules[2], rules[3], rules[4]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);

        auto rules_to_exclude = ctx.filter_rules(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 5);
        EXPECT_NE(rules_to_exclude.find(rules[0]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[1]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[2]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[3]), rules_to_exclude.end());
        EXPECT_NE(rules_to_exclude.find(rules[4]), rules_to_exclude.end());
    }

    {
        auto filter = std::make_shared<rule_filter>("3", std::vector<condition::ptr>{},
            std::set<ddwaf::rule::ptr>{rules[0], rules[5], rules[6]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);

        auto rules_to_exclude = ctx.filter_rules(deadline);
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
        auto filter = std::make_shared<rule_filter>("4", std::vector<condition::ptr>{},
            std::set<ddwaf::rule::ptr>{rules[7], rules[8], rules[6]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);

        auto rules_to_exclude = ctx.filter_rules(deadline);
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

    {
        auto filter = std::make_shared<rule_filter>("5", std::vector<condition::ptr>{},
            std::set<ddwaf::rule::ptr>{rules[0], rules[1], rules[2], rules[3], rules[4], rules[5],
                rules[6], rules[7], rules[8]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);

        auto rules_to_exclude = ctx.filter_rules(deadline);
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

TEST(TestContext, MultipleRuleFiltersNonOverlappingRulesWithConditions)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;

    // Generate rule
    constexpr unsigned num_rules = 10;
    std::vector<ddwaf::rule::ptr> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<ddwaf::rule>(std::string(id), "name", std::move(tags),
            std::vector<ddwaf::condition::ptr>{}, std::vector<std::string>{}));

        ruleset->insert_rule(rules.back());
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<rule_filter>("1", std::move(conditions),
            std::set<ddwaf::rule::ptr>{rules[0], rules[1], rules[2], rules[3], rules[4]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<rule_filter>("2", std::move(conditions),
            std::set<ddwaf::rule::ptr>{rules[5], rules[6], rules[7], rules[8], rules[9]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);
    }

    ruleset->manifest = mb.build_manifest();

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.filter_rules(deadline);
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

        auto rules_to_exclude = ctx.filter_rules(deadline);
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

TEST(TestContext, MultipleRuleFiltersOverlappingRulesWithConditions)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ddwaf::manifest_builder mb;

    // Generate rule
    constexpr unsigned num_rules = 10;
    std::vector<ddwaf::rule::ptr> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<ddwaf::rule>(std::string(id), "name", std::move(tags),
            std::vector<ddwaf::condition::ptr>{}, std::vector<std::string>{}));

        ruleset->insert_rule(rules.back());
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<rule_filter>("1", std::move(conditions),
            std::set<ddwaf::rule::ptr>{
                rules[0], rules[1], rules[2], rules[3], rules[4], rules[5], rules[6]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));

        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));

        std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

        auto filter = std::make_shared<rule_filter>("2", std::move(conditions),
            std::set<ddwaf::rule::ptr>{
                rules[3], rules[4], rules[5], rules[6], rules[7], rules[8], rules[9]});
        ruleset->rule_filters.emplace(filter->get_id(), filter);
    }

    ruleset->manifest = mb.build_manifest();

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.filter_rules(deadline);
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

        auto rules_to_exclude = ctx.filter_rules(deadline);
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

TEST(TestContext, InputFilterExclude)
{
    ddwaf::manifest_builder mb;
    auto client_ip = mb.insert("http.client_ip", {});

    std::vector<ddwaf::manifest::target_type> targets{client_ip};
    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>(
        "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

    object_filter obj_filter;
    obj_filter.insert(client_ip);

    std::vector<condition::ptr> filter_conditions;
    std::set<rule::ptr> filter_rules{rule};
    auto filter = std::make_shared<input_filter>(
        "1", std::move(filter_conditions), std::move(filter_rules), std::move(obj_filter));

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->manifest = mb.build_manifest();
    ruleset->input_filters.emplace(filter->get_id(), filter);

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    auto objects_to_exclude = ctx.filter_inputs({}, deadline);
    EXPECT_EQ(objects_to_exclude.size(), 1);
    auto events = ctx.match({}, objects_to_exclude, deadline);
    EXPECT_EQ(events.size(), 0);
}

TEST(TestContext, InputFilterExcludeRule)
{
    ddwaf::manifest_builder mb;
    auto client_ip = mb.insert("http.client_ip", {});

    std::vector<ddwaf::manifest::target_type> targets{client_ip};
    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>(
        "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

    object_filter obj_filter;
    obj_filter.insert(client_ip);

    std::vector<condition::ptr> filter_conditions;
    std::set<rule::ptr> filter_rules{rule};
    auto filter = std::make_shared<input_filter>(
        "1", std::move(filter_conditions), std::move(filter_rules), std::move(obj_filter));

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->manifest = mb.build_manifest();
    ruleset->input_filters.emplace(filter->get_id(), filter);

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    // The rule is added to the filter stage so that it's excluded from the
    // final result, since we're not actually excluding the rule from the match
    // stage we still get an event.
    auto objects_to_exclude = ctx.filter_inputs({rule}, deadline);
    EXPECT_EQ(objects_to_exclude.size(), 0);
    auto events = ctx.match({}, objects_to_exclude, deadline);
    EXPECT_EQ(events.size(), 1);
}

TEST(TestContext, InputFilterWithCondition)
{
    ddwaf::manifest_builder mb;
    auto client_ip = mb.insert("http.client_ip", {});
    auto usr_id = mb.insert("usr.id", {});

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        std::vector<std::shared_ptr<condition>> conditions;
        std::vector<ddwaf::manifest::target_type> targets{client_ip};
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.emplace_back(std::move(cond));

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        object_filter obj_filter;
        obj_filter.insert(client_ip);

        std::vector<std::shared_ptr<condition>> conditions;
        std::vector<ddwaf::manifest::target_type> targets{usr_id};
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.emplace_back(std::move(cond));

        std::set<rule::ptr> filter_rules{ruleset->rules["id"]};
        auto filter = std::make_shared<input_filter>(
            "1", std::move(conditions), std::move(filter_rules), std::move(obj_filter));

        ruleset->input_filters.emplace(filter->get_id(), filter);
    }

    ruleset->manifest = mb.build_manifest();

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 0);
        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 1);
    }

    // With usr.id != admin, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admino"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 0);
        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 1);
    }

    // With usr.id == admin, there should be no matches
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 1);
        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, InputFilterMultipleRules)
{
    ddwaf::manifest_builder mb;
    auto client_ip = mb.insert("http.client_ip", {});
    auto usr_id = mb.insert("usr.id", {});

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        std::vector<std::shared_ptr<condition>> conditions;
        std::vector<ddwaf::manifest::target_type> targets{client_ip};
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.emplace_back(std::move(cond));

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "ip_id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<std::shared_ptr<condition>> conditions;
        std::vector<ddwaf::manifest::target_type> targets{usr_id};
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.emplace_back(std::move(cond));

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "usr_id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        object_filter obj_filter;
        obj_filter.insert(client_ip);
        obj_filter.insert(usr_id);

        std::vector<std::shared_ptr<condition>> conditions;
        std::set<rule::ptr> filter_rules{ruleset->rules["usr_id"], ruleset->rules["ip_id"]};
        auto filter = std::make_shared<input_filter>(
            "1", std::move(conditions), std::move(filter_rules), std::move(obj_filter));

        ruleset->input_filters.emplace(filter->get_id(), filter);
    }

    ruleset->manifest = mb.build_manifest();

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, objects] : objects_to_exclude) { EXPECT_EQ(objects.size(), 1); }

        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }

    // With usr.id != admin, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admino"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, objects] : objects_to_exclude) { EXPECT_EQ(objects.size(), 2); }

        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }

    // With usr.id == admin, there should be no matches
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, objects] : objects_to_exclude) { EXPECT_EQ(objects.size(), 2); }

        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, InputFilterMultipleRulesMultipleFilters)
{
    ddwaf::manifest_builder mb;
    auto client_ip = mb.insert("http.client_ip", {});
    auto usr_id = mb.insert("usr.id", {});

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        std::vector<std::shared_ptr<condition>> conditions;
        std::vector<ddwaf::manifest::target_type> targets{client_ip};
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.emplace_back(std::move(cond));

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "ip_id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<std::shared_ptr<condition>> conditions;
        std::vector<ddwaf::manifest::target_type> targets{usr_id};
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.emplace_back(std::move(cond));

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "usr_id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        object_filter obj_filter;
        obj_filter.insert(client_ip);

        std::vector<std::shared_ptr<condition>> conditions;
        std::set<rule::ptr> filter_rules{ruleset->rules["ip_id"]};
        auto filter = std::make_shared<input_filter>(
            "1", std::move(conditions), std::move(filter_rules), std::move(obj_filter));

        ruleset->input_filters.emplace(filter->get_id(), filter);
    }

    {
        object_filter obj_filter;
        obj_filter.insert(usr_id);

        std::vector<std::shared_ptr<condition>> conditions;
        std::set<rule::ptr> filter_rules{ruleset->rules["usr_id"]};
        auto filter = std::make_shared<input_filter>(
            "2", std::move(conditions), std::move(filter_rules), std::move(obj_filter));

        ruleset->input_filters.emplace(filter->get_id(), filter);
    }

    ruleset->manifest = mb.build_manifest();

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 1);
        for (const auto &[rule, objects] : objects_to_exclude) { EXPECT_EQ(objects.size(), 1); }

        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }

    // With usr.id != admin, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admino"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, objects] : objects_to_exclude) { EXPECT_EQ(objects.size(), 1); }

        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }

    // With usr.id == admin, there should be no matches
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, objects] : objects_to_exclude) { EXPECT_EQ(objects.size(), 1); }

        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, InputFilterMultipleRulesMultipleFiltersMultipleObjects)
{
    ddwaf::manifest_builder mb;
    auto client_ip = mb.insert("http.client_ip", {});
    auto usr_id = mb.insert("usr.id", {});
    auto cookie_header = mb.insert("server.request.headers", {"cookie"});

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        std::vector<std::shared_ptr<condition>> conditions;
        std::vector<ddwaf::manifest::target_type> targets{client_ip};
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.emplace_back(std::move(cond));

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "ip_id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<std::shared_ptr<condition>> conditions;
        std::vector<ddwaf::manifest::target_type> targets{usr_id};
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.emplace_back(std::move(cond));

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "usr_id", "name", std::move(tags), std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    {
        std::vector<std::shared_ptr<condition>> conditions;
        std::vector<ddwaf::manifest::target_type> targets{cookie_header};
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"mycookie"}));
        conditions.emplace_back(std::move(cond));

        std::unordered_map<std::string, std::string> tags{
            {"type", "cookie_type"}, {"category", "category"}};

        auto rule = std::make_shared<ddwaf::rule>("cookie_id", "name", std::move(tags),
            std::move(conditions), std::vector<std::string>{});

        ruleset->insert_rule(rule);
    }

    auto ip_rule = ruleset->rules["ip_id"];
    auto usr_rule = ruleset->rules["usr_id"];
    auto cookie_rule = ruleset->rules["cookie_id"];
    {
        object_filter obj_filter;
        obj_filter.insert(client_ip);
        obj_filter.insert(cookie_header);

        std::vector<std::shared_ptr<condition>> conditions;
        std::set<rule::ptr> filter_rules{ip_rule, cookie_rule};
        auto filter = std::make_shared<input_filter>(
            "1", std::move(conditions), std::move(filter_rules), std::move(obj_filter));

        ruleset->input_filters.emplace(filter->get_id(), filter);
    }

    {
        object_filter obj_filter;
        obj_filter.insert(usr_id);
        obj_filter.insert(client_ip);

        std::vector<std::shared_ptr<condition>> conditions;
        std::set<rule::ptr> filter_rules{usr_rule, ip_rule};
        auto filter = std::make_shared<input_filter>(
            "2", std::move(conditions), std::move(filter_rules), std::move(obj_filter));

        ruleset->input_filters.emplace(filter->get_id(), filter);
    }

    {
        object_filter obj_filter;
        obj_filter.insert(usr_id);
        obj_filter.insert(cookie_header);

        std::vector<std::shared_ptr<condition>> conditions;
        std::set<rule::ptr> filter_rules{usr_rule, cookie_rule};
        auto filter = std::make_shared<input_filter>(
            "3", std::move(conditions), std::move(filter_rules), std::move(obj_filter));

        ruleset->input_filters.emplace(filter->get_id(), filter);
    }

    ruleset->manifest = mb.build_manifest();

    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, objects] : objects_to_exclude) {
            EXPECT_EQ(objects.size(), 1);
            EXPECT_NE(objects.find(&root.array[0]), objects.end());
        }

        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }

    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, objects] : objects_to_exclude) {
            EXPECT_EQ(objects.size(), 1);
            EXPECT_NE(objects.find(&root.array[0]), objects.end());
        }

        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }

    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object headers;
        ddwaf_object tmp;
        ddwaf_object_map(&headers);
        ddwaf_object_map_add(&headers, "cookie", ddwaf_object_string(&tmp, "mycookie"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "server.request.headers", &headers);

        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, objects] : objects_to_exclude) {
            EXPECT_EQ(objects.size(), 1);
            EXPECT_NE(objects.find(&root.array[0]), objects.end());
        }

        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }

    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, objects] : objects_to_exclude) {
            EXPECT_EQ(objects.size(), 2);
            EXPECT_NE(objects.find(&root.array[0]), objects.end());
            EXPECT_NE(objects.find(&root.array[1]), objects.end());
        }
        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }

    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object headers;
        ddwaf_object tmp;
        ddwaf_object_map(&headers);
        ddwaf_object_map_add(&headers, "cookie", ddwaf_object_string(&tmp, "mycookie"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&root, "server.request.headers", &headers);

        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, objects] : objects_to_exclude) {
            EXPECT_EQ(objects.size(), 2);
            EXPECT_NE(objects.find(&root.array[0]), objects.end());
            EXPECT_NE(objects.find(&root.array[1]), objects.end());
        }
        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }

    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object headers;
        ddwaf_object tmp;
        ddwaf_object_map(&headers);
        ddwaf_object_map_add(&headers, "cookie", ddwaf_object_string(&tmp, "mycookie"));

        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&root, "server.request.headers", &headers);

        ctx.insert(root);

        auto objects_to_exclude = ctx.filter_inputs({}, deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, objects] : objects_to_exclude) {
            EXPECT_EQ(objects.size(), 3);
            EXPECT_NE(objects.find(&root.array[0]), objects.end());
            EXPECT_NE(objects.find(&root.array[1]), objects.end());
            EXPECT_NE(objects.find(&root.array[2]), objects.end());
        }
        auto events = ctx.match({}, objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}
