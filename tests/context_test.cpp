// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "context.hpp"
#include "exception.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "expression.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"
#include "test.hpp"

#include <gmock/gmock.h>

using ::testing::_;
using ::testing::Return;
using ::testing::Sequence;

using namespace ddwaf;
using namespace std::literals;
using namespace ddwaf::exclusion;
using attribute = object_store::attribute;

namespace ddwaf::test {
class context : public ddwaf::context {
public:
    explicit context(std::shared_ptr<ddwaf::ruleset> ruleset) : ddwaf::context(std::move(ruleset))
    {}

    bool insert(ddwaf_object &object, attribute attr = attribute::none)
    {
        return store_.insert(object, attr);
    }
};

} // namespace ddwaf::test

namespace {

namespace mock {

class rule : public ddwaf::rule {
public:
    using ptr = std::shared_ptr<mock::rule>;

    rule(std::string id, std::string name, std::unordered_map<std::string, std::string> tags,
        std::shared_ptr<expression> expr, std::vector<std::string> actions = {},
        bool enabled = true, source_type source = source_type::base)
        : ddwaf::rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled, source)
    {}
    ~rule() override = default;

    MOCK_METHOD(std::optional<event>, match,
        (const object_store &, rule::cache_type &, (const exclusion::object_set_ref &objects),
            (const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &),
            ddwaf::timer &),
        (const override));
};

class rule_filter : public ddwaf::exclusion::rule_filter {
public:
    using ptr = std::shared_ptr<mock::rule_filter>;

    rule_filter(std::string id, std::shared_ptr<expression> expr,
        std::set<ddwaf::rule *> rule_targets, filter_mode mode = filter_mode::bypass)
        : exclusion::rule_filter(std::move(id), std::move(expr), std::move(rule_targets), mode)
    {}
    ~rule_filter() override = default;

    MOCK_METHOD(std::optional<ddwaf::exclusion::rule_filter::excluded_set>, match,
        (const object_store &store, cache_type &cache, ddwaf::timer &deadline), (const override));
};

class input_filter : public ddwaf::exclusion::input_filter {
public:
    using ptr = std::shared_ptr<mock::input_filter>;

    input_filter(std::string id, std::shared_ptr<expression> expr,
        std::set<ddwaf::rule *> rule_targets, std::shared_ptr<object_filter> filter)
        : exclusion::input_filter(
              std::move(id), std::move(expr), std::move(rule_targets), std::move(filter))
    {}
    ~input_filter() override = default;

    MOCK_METHOD(std::optional<excluded_set>, match,
        (const object_store &store, cache_type &cache, ddwaf::timer &deadline), (const override));
};

class processor : public ddwaf::processor {
public:
    processor() : ddwaf::processor({}, {}, {}, {}, {}, true, true) {}
    ~processor() override = default;

    MOCK_METHOD(void, eval,
        (object_store & store, optional_ref<ddwaf_object> &, processor::cache_type &,
            ddwaf::timer &deadline),
        (const override));
};

} // namespace mock

TEST(TestContext, PreprocessorEval)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());
    auto proc = std::make_shared<mock::processor>();

    Sequence seq;

    EXPECT_CALL(*proc, eval(_, _, _, _)).InSequence(seq);
    EXPECT_CALL(*rule, match(_, _, _, _, _)).InSequence(seq).WillOnce(Return(std::nullopt));

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->preprocessors.emplace("id", proc);
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

    ddwaf::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ctx.run(root, std::nullopt, std::nullopt, 20000);
}

TEST(TestContext, PostprocessorEval)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());
    auto proc = std::make_shared<mock::processor>();

    Sequence seq;

    EXPECT_CALL(*rule, match(_, _, _, _, _)).InSequence(seq).WillOnce(Return(std::nullopt));
    EXPECT_CALL(*proc, eval(_, _, _, _)).InSequence(seq);

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->postprocessors.emplace("id", proc);
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

    ddwaf::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ctx.run(root, std::nullopt, std::nullopt, 20000);
}

TEST(TestContext, SkipRuleNoTargets)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

    EXPECT_CALL(*rule, match(_, _, _, _, _)).Times(0);

    ddwaf::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ctx.run(root, std::nullopt, std::nullopt, 20000);
}

TEST(TestContext, MatchTimeout)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);

    ddwaf::timer deadline{0s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    EXPECT_THROW(ctx.eval_rules({}, deadline), ddwaf::timeout_exception);
}

TEST(TestContext, NoMatch)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));
    ctx.insert(root);

    auto events = ctx.eval_rules({}, deadline);
    EXPECT_EQ(events.size(), 0);
}

TEST(TestContext, Match)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    auto events = ctx.eval_rules({}, deadline);
    EXPECT_EQ(events.size(), 1);
}

TEST(TestContext, MatchMultipleRulesInCollectionSingleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.eval_rules({}, deadline);
    EXPECT_EQ(events.size(), 1);

    auto &event = events[0];
    EXPECT_STREQ(event.rule->get_id().c_str(), "id1");
    EXPECT_STREQ(event.rule->get_name().c_str(), "name1");
    EXPECT_STREQ(event.rule->get_tag("type").data(), "type");
    EXPECT_STREQ(event.rule->get_tag("category").data(), "category1");
    std::vector<std::string> expected_actions{};
    EXPECT_EQ(event.rule->get_actions(), expected_actions);
    EXPECT_EQ(event.matches.size(), 1);

    auto &match = event.matches[0];
    EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
    EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
    EXPECT_STREQ(match.operator_name.data(), "ip_match");
    EXPECT_STREQ(match.operator_value.data(), "");
    EXPECT_STREQ(match.address.data(), "http.client_ip");
    EXPECT_TRUE(match.key_path.empty());
}

TEST(TestContext, MatchMultipleRulesWithPrioritySingleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), builder.build(), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    {
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        ddwaf::timer deadline{2s};
        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto event = events[0];
        EXPECT_STREQ(event.rule->get_id().c_str(), "id2");
        EXPECT_EQ(event.rule->get_actions().size(), 1);
        EXPECT_STREQ(event.rule->get_actions()[0].data(), "block");
    }

    {
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        ddwaf::timer deadline{2s};
        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto event = events[0];
        EXPECT_STREQ(event.rule->get_id().c_str(), "id2");
        EXPECT_EQ(event.rule->get_actions().size(), 1);
        EXPECT_STREQ(event.rule->get_actions()[0].data(), "block");
    }
}

TEST(TestContext, MatchMultipleRulesInCollectionDoubleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STREQ(event.rule->get_id().c_str(), "id1");
        EXPECT_STREQ(event.rule->get_name().c_str(), "name1");
        EXPECT_STREQ(event.rule->get_tag("type").data(), "type");
        EXPECT_STREQ(event.rule->get_tag("category").data(), "category1");
        std::vector<std::string> expected_actions{};
        EXPECT_EQ(event.rule->get_actions(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.operator_name.data(), "ip_match");
        EXPECT_STREQ(match.operator_value.data(), "");
        EXPECT_STREQ(match.address.data(), "http.client_ip");
        EXPECT_TRUE(match.key_path.empty());
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, MatchMultipleRulesWithPriorityDoubleRunPriorityLast)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), builder.build(), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STREQ(event.rule->get_id().c_str(), "id1");
        EXPECT_STREQ(event.rule->get_name().c_str(), "name1");
        EXPECT_STREQ(event.rule->get_tag("type").data(), "type");
        EXPECT_STREQ(event.rule->get_tag("category").data(), "category1");
        std::vector<std::string> expected_actions{};
        EXPECT_EQ(event.rule->get_actions(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.operator_name.data(), "ip_match");
        EXPECT_STREQ(match.operator_value.data(), "");
        EXPECT_STREQ(match.address.data(), "http.client_ip");
        EXPECT_TRUE(match.key_path.empty());
    }

    {
        // An existing match in a collection will not inhibit a match in a
        // priority collection.
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_EQ(events.size(), 1);
        EXPECT_STREQ(event.rule->get_id().c_str(), "id2");
        EXPECT_STREQ(event.rule->get_name().c_str(), "name2");
        EXPECT_STREQ(event.rule->get_tag("type").data(), "type");
        EXPECT_STREQ(event.rule->get_tag("category").data(), "category2");
        std::vector<std::string> expected_actions{"block"};
        EXPECT_EQ(event.rule->get_actions(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.resolved.c_str(), "admin");
        EXPECT_STREQ(match.matched.c_str(), "admin");
        EXPECT_STREQ(match.operator_name.data(), "exact_match");
        EXPECT_STREQ(match.operator_value.data(), "");
        EXPECT_STREQ(match.address.data(), "usr.id");
        EXPECT_TRUE(match.key_path.empty());
    }
}

TEST(TestContext, MatchMultipleRulesWithPriorityDoubleRunPriorityFirst)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), builder.build(), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STREQ(event.rule->get_id().c_str(), "id1");
        EXPECT_STREQ(event.rule->get_name().c_str(), "name1");
        EXPECT_STREQ(event.rule->get_tag("type").data(), "type");
        EXPECT_STREQ(event.rule->get_tag("category").data(), "category1");
        std::vector<std::string> expected_actions{"block"};
        EXPECT_EQ(event.rule->get_actions(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.operator_name.data(), "ip_match");
        EXPECT_STREQ(match.operator_value.data(), "");
        EXPECT_STREQ(match.address.data(), "http.client_ip");
        EXPECT_TRUE(match.key_path.empty());
    }

    {
        // An existing match in a collection will not inhibit a match in a
        // priority collection.
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, MatchMultipleRulesWithPriorityUntilAllActionsMet)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), builder.build(), std::vector<std::string>{"redirect"});

        ruleset->insert_rule(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STREQ(event.rule->get_id().c_str(), "id1");
        EXPECT_STREQ(event.rule->get_name().c_str(), "name1");
        EXPECT_STREQ(event.rule->get_tag("type").data(), "type");
        EXPECT_STREQ(event.rule->get_tag("category").data(), "category1");
        EXPECT_TRUE(event.rule->get_actions().empty());

        auto &match = event.matches[0];
        EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.operator_name.data(), "ip_match");
        EXPECT_STREQ(match.operator_value.data(), "");
        EXPECT_STREQ(match.address.data(), "http.client_ip");
        EXPECT_TRUE(match.key_path.empty());
    }

    {
        // An existing match in a collection will not inhibit a match in a
        // priority collection.
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_EQ(events.size(), 1);
        EXPECT_STREQ(event.rule->get_id().c_str(), "id2");
        EXPECT_STREQ(event.rule->get_name().c_str(), "name2");
        EXPECT_STREQ(event.rule->get_tag("type").data(), "type");
        EXPECT_STREQ(event.rule->get_tag("category").data(), "category2");
        std::vector<std::string> expected_actions{"redirect"};
        EXPECT_EQ(event.rule->get_actions(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.resolved.c_str(), "admin");
        EXPECT_STREQ(match.matched.c_str(), "admin");
        EXPECT_STREQ(match.operator_name.data(), "exact_match");
        EXPECT_STREQ(match.operator_value.data(), "");
        EXPECT_STREQ(match.address.data(), "usr.id");
        EXPECT_TRUE(match.key_path.empty());
    }
}

TEST(TestContext, MatchMultipleCollectionsSingleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.eval_rules({}, deadline);
    EXPECT_EQ(events.size(), 2);
}

TEST(TestContext, MatchMultiplePriorityCollectionsSingleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), builder.build(), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), builder.build(), std::vector<std::string>{"redirect"});

        ruleset->insert_rule(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.eval_rules({}, deadline);
    EXPECT_EQ(events.size(), 2);
}

TEST(TestContext, MatchMultipleCollectionsDoubleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>("id1", "name1", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>("id2", "name2", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);
    }
}

TEST(TestContext, MatchMultiplePriorityCollectionsDoubleRun)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id1", "name1", std::move(tags), builder.build(), std::vector<std::string>{"block"});

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        auto rule = std::make_shared<ddwaf::rule>(
            "id2", "name2", std::move(tags), builder.build(), std::vector<std::string>{"redirect"});

        ruleset->insert_rule(rule);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);
    }
}

TEST(TestContext, SkipRuleFilterNoTargets)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    std::shared_ptr<mock::rule> rule;
    std::shared_ptr<mock::rule_filter> filter;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        filter = std::make_shared<mock::rule_filter>(
            "1", builder.build(), std::set<ddwaf::rule *>{rule.get()});

        ruleset->insert_filter<exclusion::rule_filter>(filter);
    }
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

    EXPECT_CALL(*rule, match(_, _, _, _, _)).Times(0);
    EXPECT_CALL(*filter, match(_, _, _)).Times(0);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "user_name", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::context ctx(ruleset);
    ctx.run(root, std::nullopt, std::nullopt, 20000);
}

TEST(TestContext, SkipRuleButNotRuleFilterNoTargets)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    std::shared_ptr<mock::rule> rule;
    std::shared_ptr<mock::rule_filter> filter;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        filter = std::make_shared<mock::rule_filter>(
            "1", builder.build(), std::set<ddwaf::rule *>{rule.get()});

        ruleset->insert_filter<exclusion::rule_filter>(filter);
    }
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

    EXPECT_CALL(*rule, match(_, _, _, _, _)).Times(0);
    EXPECT_CALL(*filter, match(_, _, _)).WillOnce(Return(std::nullopt));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "user_name", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::context ctx(ruleset);
    ctx.run(root, std::nullopt, std::nullopt, 20000);
}

TEST(TestContext, RuleFilterWithCondition)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    std::shared_ptr<rule> rule;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        auto filter = std::make_shared<rule_filter>(
            "1", builder.build(), std::set<ddwaf::rule *>{rule.get()});
        ruleset->insert_filter(filter);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    auto rules_to_exclude = ctx.eval_filters(deadline);
    EXPECT_EQ(rules_to_exclude.size(), 1);
    EXPECT_TRUE(rules_to_exclude.contains(rule.get()));

    auto events = ctx.eval_rules(rules_to_exclude, deadline);
    EXPECT_EQ(events.size(), 0);
}

TEST(TestContext, RuleFilterWithEphemeralConditionMatch)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    std::shared_ptr<rule> rule;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        auto filter = std::make_shared<rule_filter>(
            "1", builder.build(), std::set<ddwaf::rule *>{rule.get()});
        ruleset->insert_filter(filter);
    }

    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral;
        ddwaf_object persistent;

        ddwaf_object_map(&ephemeral);
        ddwaf_object_map_add(
            &ephemeral, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object_map(&persistent);
        ddwaf_object_map_add(&persistent, "usr.id", ddwaf_object_string(&tmp, "admin"));

        EXPECT_EQ(ctx.run(persistent, ephemeral, {}, LONG_TIME), DDWAF_OK);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        EXPECT_EQ(ctx.run(root, {}, {}, LONG_TIME), DDWAF_MATCH);
    }
}

TEST(TestContext, OverlappingRuleFiltersEphemeralBypassPersistentMonitor)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    std::shared_ptr<rule> rule;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());
        rule->set_actions({"block"});
        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        auto filter = std::make_shared<rule_filter>(
            "1", builder.build(), std::set<ddwaf::rule *>{rule.get()});
        ruleset->insert_filter(filter);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"unrouted"});
        builder.add_target("http.route");

        auto filter = std::make_shared<rule_filter>("2", builder.build(),
            std::set<ddwaf::rule *>{rule.get()}, exclusion::filter_mode::monitor);
        ruleset->insert_filter(filter);
    }

    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral;
        ddwaf_object persistent;

        ddwaf_object_map(&ephemeral);
        ddwaf_object_map_add(
            &ephemeral, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object_map(&persistent);
        ddwaf_object_map_add(&persistent, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&persistent, "http.route", ddwaf_object_string(&tmp, "unrouted"));

        EXPECT_EQ(ctx.run(persistent, ephemeral, {}, LONG_TIME), DDWAF_OK);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf_result result = DDWAF_RESULT_INITIALISER;
        EXPECT_EQ(ctx.run(root, {}, result, LONG_TIME), DDWAF_MATCH);
        EXPECT_EQ(ddwaf_object_size(&result.actions), 0);
        ddwaf_result_free(&result);
    }
}

TEST(TestContext, OverlappingRuleFiltersEphemeralMonitorPersistentBypass)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    std::shared_ptr<rule> rule;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());
        rule->set_actions({"block"});
        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        auto filter = std::make_shared<rule_filter>("1", builder.build(),
            std::set<ddwaf::rule *>{rule.get()}, exclusion::filter_mode::monitor);
        ruleset->insert_filter(filter);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"unrouted"});
        builder.add_target("http.route");

        auto filter = std::make_shared<rule_filter>(
            "2", builder.build(), std::set<ddwaf::rule *>{rule.get()});
        ruleset->insert_filter(filter);
    }

    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object tmp;
        ddwaf_object ephemeral;
        ddwaf_object persistent;

        ddwaf_object_map(&ephemeral);
        ddwaf_object_map_add(
            &ephemeral, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object_map(&persistent);
        ddwaf_object_map_add(&persistent, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ddwaf_object_map_add(&persistent, "http.route", ddwaf_object_string(&tmp, "unrouted"));

        EXPECT_EQ(ctx.run(persistent, ephemeral, {}, LONG_TIME), DDWAF_OK);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        EXPECT_EQ(ctx.run(root, {}, {}, LONG_TIME), DDWAF_OK);
    }
}

TEST(TestContext, RuleFilterTimeout)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    std::shared_ptr<rule> rule;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        auto filter = std::make_shared<rule_filter>(
            "1", builder.build(), std::set<ddwaf::rule *>{rule.get()});
        ruleset->insert_filter(filter);
    }

    ddwaf::timer deadline{0s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    EXPECT_THROW(ctx.eval_filters(deadline), ddwaf::timeout_exception);
}

TEST(TestContext, NoRuleFilterWithCondition)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    std::shared_ptr<rule> rule;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        auto filter = std::make_shared<rule_filter>(
            "1", builder.build(), std::set<ddwaf::rule *>{rule.get()});
        ruleset->insert_filter(filter);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.2"));
    ctx.insert(root);

    auto rules_to_exclude = ctx.eval_filters(deadline);
    EXPECT_TRUE(rules_to_exclude.empty());

    auto events = ctx.eval_rules(rules_to_exclude, deadline);
    EXPECT_EQ(events.size(), 1);
}

TEST(TestContext, MultipleRuleFiltersNonOverlappingRules)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    constexpr unsigned num_rules = 9;
    std::vector<std::shared_ptr<rule>> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<ddwaf::rule>("id" + std::to_string(i), "name",
            std::move(tags), std::make_shared<expression>(), std::vector<std::string>{}));

        ruleset->insert_rule(rules.back());
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 0);
    }

    {
        auto filter = std::make_shared<rule_filter>("1", std::make_shared<expression>(),
            std::set<ddwaf::rule *>{rules[0].get(), rules[1].get(), rules[2].get()});
        ruleset->insert_filter(filter);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 3);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
    }

    {
        auto filter = std::make_shared<rule_filter>("2", std::make_shared<expression>(),
            std::set<ddwaf::rule *>{rules[3].get(), rules[4].get(), rules[5].get()});
        ruleset->insert_filter(filter);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 6);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5].get()));
    }

    {
        auto filter = std::make_shared<rule_filter>("3", std::make_shared<expression>(),
            std::set<ddwaf::rule *>{rules[6].get(), rules[7].get(), rules[8].get()});
        ruleset->insert_filter(filter);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8].get()));
    }
}

TEST(TestContext, MultipleRuleFiltersOverlappingRules)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    constexpr unsigned num_rules = 9;
    std::vector<std::shared_ptr<rule>> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<ddwaf::rule>(std::string(id), "name", std::move(tags),
            std::make_shared<expression>(), std::vector<std::string>{}));

        ruleset->insert_rule(rules.back());
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 0);
    }

    {
        auto filter = std::make_shared<rule_filter>("1", std::make_shared<expression>(),
            std::set<ddwaf::rule *>{
                rules[0].get(), rules[1].get(), rules[2].get(), rules[3].get()});
        ruleset->insert_filter(filter);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 4);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3].get()));
    }

    {
        auto filter = std::make_shared<rule_filter>("2", std::make_shared<expression>(),
            std::set<ddwaf::rule *>{rules[2].get(), rules[3].get(), rules[4].get()});
        ruleset->insert_filter(filter);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 5);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4].get()));
    }

    {
        auto filter = std::make_shared<rule_filter>("3", std::make_shared<expression>(),
            std::set<ddwaf::rule *>{rules[0].get(), rules[5].get(), rules[6].get()});
        ruleset->insert_filter(filter);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 7);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6].get()));
    }

    {
        auto filter = std::make_shared<rule_filter>("4", std::make_shared<expression>(),
            std::set<ddwaf::rule *>{rules[7].get(), rules[8].get(), rules[6].get()});
        ruleset->insert_filter(filter);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8].get()));
    }

    {
        auto filter = std::make_shared<rule_filter>("5", std::make_shared<expression>(),
            std::set<ddwaf::rule *>{rules[0].get(), rules[1].get(), rules[2].get(), rules[3].get(),
                rules[4].get(), rules[5].get(), rules[6].get(), rules[7].get(), rules[8].get()});
        ruleset->insert_filter(filter);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8].get()));
    }
}

TEST(TestContext, MultipleRuleFiltersNonOverlappingRulesWithConditions)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    constexpr unsigned num_rules = 10;
    std::vector<std::shared_ptr<rule>> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<ddwaf::rule>(std::string(id), "name", std::move(tags),
            std::make_shared<expression>(), std::vector<std::string>{}));

        ruleset->insert_rule(rules.back());
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        auto filter = std::make_shared<rule_filter>("1", builder.build(),
            std::set<ddwaf::rule *>{
                rules[0].get(), rules[1].get(), rules[2].get(), rules[3].get(), rules[4].get()});
        ruleset->insert_filter(filter);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        auto filter = std::make_shared<rule_filter>("2", builder.build(),
            std::set<ddwaf::rule *>{
                rules[5].get(), rules[6].get(), rules[7].get(), rules[8].get(), rules[9].get()});
        ruleset->insert_filter(filter);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 5);
        EXPECT_TRUE(rules_to_exclude.contains(rules[5].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[9].get()));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 10);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[9].get()));
    }
}

TEST(TestContext, MultipleRuleFiltersOverlappingRulesWithConditions)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    constexpr unsigned num_rules = 10;
    std::vector<std::shared_ptr<rule>> rules;
    rules.reserve(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules.emplace_back(std::make_shared<ddwaf::rule>(std::string(id), "name", std::move(tags),
            std::make_shared<expression>(), std::vector<std::string>{}));

        ruleset->insert_rule(rules.back());
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        auto filter = std::make_shared<rule_filter>("1", builder.build(),
            std::set<ddwaf::rule *>{rules[0].get(), rules[1].get(), rules[2].get(), rules[3].get(),
                rules[4].get(), rules[5].get(), rules[6].get()});
        ruleset->insert_filter(filter);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        auto filter = std::make_shared<rule_filter>("2", builder.build(),
            std::set<ddwaf::rule *>{rules[3].get(), rules[4].get(), rules[5].get(), rules[6].get(),
                rules[7].get(), rules[8].get(), rules[9].get()});
        ruleset->insert_filter(filter);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 7);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6].get()));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 10);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8].get()));
        EXPECT_TRUE(rules_to_exclude.contains(rules[9].get()));
    }
}

TEST(TestContext, SkipInputFilterNoTargets)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    std::shared_ptr<mock::rule> rule;
    std::shared_ptr<mock::input_filter> filter;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<ddwaf::rule *> eval_filters{rule.get()};
        filter = std::make_shared<mock::input_filter>(
            "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));
        ruleset->insert_filter<exclusion::input_filter>(filter);
    }
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

    EXPECT_CALL(*rule, match(_, _, _, _, _)).Times(0);
    EXPECT_CALL(*filter, match(_, _, _)).Times(0);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "user_name", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::context ctx(ruleset);
    ctx.run(root, std::nullopt, std::nullopt, 20000);
}

TEST(TestContext, SkipRuleButNotInputFilterNoTargets)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();

    // Generate rule
    std::shared_ptr<mock::rule> rule;
    std::shared_ptr<mock::input_filter> filter;
    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    // Generate filter
    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<ddwaf::rule *> eval_filters{rule.get()};
        filter = std::make_shared<mock::input_filter>(
            "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));
        ruleset->insert_filter<exclusion::input_filter>(filter);
    }
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

    EXPECT_CALL(*rule, match(_, _, _, _, _)).Times(0);
    EXPECT_CALL(*filter, match(_, _, _)).WillOnce(Return(std::nullopt));

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "user_name", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::context ctx(ruleset);
    ctx.run(root, std::nullopt, std::nullopt, 20000);
}

TEST(TestContext, InputFilterExclude)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

    std::set<ddwaf::rule *> eval_filters{rule.get()};
    auto filter = std::make_shared<input_filter>(
        "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->insert_filter(filter);

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    auto objects_to_exclude = ctx.eval_filters(deadline);
    EXPECT_EQ(objects_to_exclude.size(), 1);

    auto events = ctx.eval_rules(objects_to_exclude, deadline);
    EXPECT_EQ(events.size(), 0);
}

TEST(TestContext, InputFilterExcludeEphemeral)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");
    builder.add_target("http.peer_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

    std::set<ddwaf::rule *> eval_filters{rule.get()};
    auto filter = std::make_shared<input_filter>(
        "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->insert_filter(filter);
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();

    ddwaf::test::context ctx(ruleset);

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        EXPECT_EQ(ctx.run({}, root, {}, LONG_TIME), DDWAF_OK);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        EXPECT_EQ(ctx.run({}, root, {}, LONG_TIME), DDWAF_OK);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.peer_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        EXPECT_EQ(ctx.run({}, root, {}, LONG_TIME), DDWAF_MATCH);
    }
}

TEST(TestContext, InputFilterExcludeEphemeralReuseObject)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");
    builder.add_target("http.peer_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

    std::set<ddwaf::rule *> eval_filters{rule.get()};
    auto filter = std::make_shared<input_filter>(
        "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->insert_rule(rule);
    ruleset->insert_filter(filter);
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();
    ruleset->free_fn = nullptr;

    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    EXPECT_EQ(ctx.run({}, root, {}, LONG_TIME), DDWAF_OK);

    std::string peer_ip = "http.peer_ip";
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    memcpy(const_cast<char *>(root.array[0].parameterName), peer_ip.c_str(), peer_ip.size());
    root.array[0].parameterNameLength = peer_ip.size();

    EXPECT_EQ(ctx.run({}, root, {}, LONG_TIME), DDWAF_MATCH);

    ddwaf_object_free(&root);
}

TEST(TestContext, InputFilterExcludeRule)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto ruleset = std::make_shared<ddwaf::ruleset>();

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());
    ruleset->insert_rule(rule);

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<ddwaf::rule *> eval_filters{rule.get()};
        auto filter = std::make_shared<input_filter>(
            "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    {
        auto filter = std::make_shared<rule_filter>(
            "1", std::make_shared<expression>(), std::set<ddwaf::rule *>{rule.get()});
        ruleset->insert_filter(filter);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    // The rule is added to the filter stage so that it's excluded from the
    // final result, since we're not actually excluding the rule from the match
    // stage we still get an event.
    auto objects_to_exclude = ctx.eval_filters(deadline);
    EXPECT_EQ(objects_to_exclude.size(), 1);

    auto it = objects_to_exclude.persistent.find(rule.get());
    it->second.mode = filter_mode::none;
    EXPECT_TRUE(it->second.objects.empty());

    auto events = ctx.eval_rules(objects_to_exclude, deadline);
    EXPECT_EQ(events.size(), 1);
}

TEST(TestContext, InputFilterExcludeRuleEphemeral)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto ruleset = std::make_shared<ddwaf::ruleset>();

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());
    ruleset->insert_rule(rule);

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<ddwaf::rule *> eval_filters{rule.get()};
        auto filter = std::make_shared<input_filter>(
            "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    {
        auto filter = std::make_shared<rule_filter>(
            "1", std::make_shared<expression>(), std::set<ddwaf::rule *>{rule.get()});
        ruleset->insert_filter(filter);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root, attribute::ephemeral);

    auto objects_to_exclude = ctx.eval_filters(deadline);
    EXPECT_EQ(objects_to_exclude.size(), 1);

    auto it = objects_to_exclude.persistent.find(rule.get());
    EXPECT_TRUE(it->second.objects.empty());

    EXPECT_FALSE(objects_to_exclude.ephemeral.contains(rule.get()));
}

TEST(TestContext, InputFilterMonitorRuleEphemeral)
{
    expression_builder builder(1);
    builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
    builder.add_target("http.client_ip");

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    auto ruleset = std::make_shared<ddwaf::ruleset>();

    auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());
    ruleset->insert_rule(rule);

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<ddwaf::rule *> eval_filters{rule.get()};
        auto filter = std::make_shared<input_filter>(
            "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    {
        auto filter = std::make_shared<rule_filter>("1", std::make_shared<expression>(),
            std::set<ddwaf::rule *>{rule.get()}, filter_mode::monitor);
        ruleset->insert_filter(filter);
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(ruleset);

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root, attribute::ephemeral);

    auto objects_to_exclude = ctx.eval_filters(deadline);
    EXPECT_EQ(objects_to_exclude.size(), 2);

    {
        auto it = objects_to_exclude.persistent.find(rule.get());
        EXPECT_TRUE(it->second.objects.empty());
    }

    {
        auto it = objects_to_exclude.ephemeral.find(rule.get());
        EXPECT_FALSE(it->second.objects.empty());
    }
}

TEST(TestContext, InputFilterWithCondition)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<ddwaf::rule *> eval_filters{ruleset->rules[0].get()};
        auto filter = std::make_shared<input_filter>(
            "1", builder.build(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 0);
        auto events = ctx.eval_rules(objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 1);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 0);
        auto events = ctx.eval_rules(objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 1);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 1);
        auto events = ctx.eval_rules(objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, InputFilterWithEphemeralCondition)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    ruleset->event_obfuscator = std::make_shared<ddwaf::obfuscator>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        auto rule = std::make_shared<ddwaf::rule>("id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<ddwaf::rule *> eval_filters{ruleset->rules[0].get()};
        auto filter = std::make_shared<input_filter>(
            "1", builder.build(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    ddwaf::test::context ctx(ruleset);
    {
        ddwaf_object persistent;
        ddwaf_object tmp;
        ddwaf_object_map(&persistent);
        ddwaf_object_map_add(
            &persistent, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf_object ephemeral;
        ddwaf_object_map(&ephemeral);
        ddwaf_object_map_add(&ephemeral, "usr.id", ddwaf_object_string(&tmp, "admin"));

        EXPECT_EQ(ctx.run(persistent, ephemeral, {}, LONG_TIME), DDWAF_OK);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        EXPECT_EQ(ctx.run(root, {}, {}, LONG_TIME), DDWAF_MATCH);
    }
}

TEST(TestContext, InputFilterMultipleRules)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        auto rule =
            std::make_shared<ddwaf::rule>("ip_id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr.id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        auto rule =
            std::make_shared<ddwaf::rule>("usr_id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
        obj_filter->insert(get_target_index("usr.id"), "usr.id");

        std::set<ddwaf::rule *> eval_filters{ruleset->rules[0].get(), ruleset->rules[1].get()};
        auto filter = std::make_shared<input_filter>(
            "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            EXPECT_EQ(policy.objects.size(), 1);
        }

        auto events = ctx.eval_rules(objects_to_exclude, deadline);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            EXPECT_EQ(policy.objects.size(), 2);
        }

        auto events = ctx.eval_rules(objects_to_exclude, deadline);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            EXPECT_EQ(policy.objects.size(), 2);
        }

        auto events = ctx.eval_rules(objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, InputFilterMultipleRulesMultipleFilters)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        auto rule =
            std::make_shared<ddwaf::rule>("ip_id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr_id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        auto rule =
            std::make_shared<ddwaf::rule>("usr_id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<ddwaf::rule *> eval_filters{ruleset->rules[0].get()};
        auto filter = std::make_shared<input_filter>(
            "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("usr.id"), "usr.id");

        std::set<ddwaf::rule *> eval_filters{ruleset->rules[1].get()};
        auto filter = std::make_shared<input_filter>(
            "2", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 1);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
        }

        auto events = ctx.eval_rules(objects_to_exclude, deadline);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
        }

        auto events = ctx.eval_rules(objects_to_exclude, deadline);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 2);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
        }

        auto events = ctx.eval_rules(objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

TEST(TestContext, InputFilterMultipleRulesMultipleFiltersMultipleObjects)
{
    auto ruleset = std::make_shared<ddwaf::ruleset>();
    {
        expression_builder builder(1);
        builder.start_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});
        builder.add_target("http.client_ip");

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        auto rule =
            std::make_shared<ddwaf::rule>("ip_id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"admin"});
        builder.add_target("usr_id");

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        auto rule =
            std::make_shared<ddwaf::rule>("usr_id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    {
        expression_builder builder(1);
        builder.start_condition<matcher::exact_match>(std::vector<std::string>{"mycookie"});
        builder.add_target("server.request.headers", {"cookie"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "cookie_type"}, {"category", "category"}};

        auto rule =
            std::make_shared<ddwaf::rule>("cookie_id", "name", std::move(tags), builder.build());

        ruleset->insert_rule(rule);
    }

    auto ip_rule = ruleset->rules[0];
    auto usr_rule = ruleset->rules[1];
    auto cookie_rule = ruleset->rules[2];

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
        obj_filter->insert(get_target_index("server.request.headers"), "server.request.headers");

        std::set<ddwaf::rule *> eval_filters{ip_rule.get(), cookie_rule.get()};
        auto filter = std::make_shared<input_filter>(
            "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("usr.id"), "usr.id");
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<ddwaf::rule *> eval_filters{usr_rule.get(), ip_rule.get()};
        auto filter = std::make_shared<input_filter>(
            "2", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("usr.id"), "usr.id");
        obj_filter->insert(get_target_index("server.request.headers"), "server.request.headers");

        std::set<ddwaf::rule *> eval_filters{usr_rule.get(), cookie_rule.get()};
        auto filter = std::make_shared<input_filter>(
            "3", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));

        ruleset->insert_filter(filter);
    }

    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(ruleset);

        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
            EXPECT_TRUE(objects.contains(&root.array[0]));
        }

        auto events = ctx.eval_rules(objects_to_exclude, deadline);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
            EXPECT_TRUE(objects.contains(&root.array[0]));
        }

        auto events = ctx.eval_rules(objects_to_exclude, deadline);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 1);
            EXPECT_TRUE(objects.contains(&root.array[0]));
        }

        auto events = ctx.eval_rules(objects_to_exclude, deadline);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 2);
            EXPECT_TRUE(objects.contains(&root.array[0]));
            EXPECT_TRUE(objects.contains(&root.array[1]));
        }
        auto events = ctx.eval_rules(objects_to_exclude, deadline);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 2);
            EXPECT_TRUE(objects.contains(&root.array[0]));
            EXPECT_TRUE(objects.contains(&root.array[1]));
        }
        auto events = ctx.eval_rules(objects_to_exclude, deadline);
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

        auto objects_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(objects_to_exclude.size(), 3);
        for (const auto &[rule, policy] : objects_to_exclude.persistent) {
            const auto &objects = policy.objects;
            EXPECT_EQ(objects.size(), 3);
            EXPECT_TRUE(objects.contains(&root.array[0]));
            EXPECT_TRUE(objects.contains(&root.array[1]));
            EXPECT_TRUE(objects.contains(&root.array[2]));
        }
        auto events = ctx.eval_rules(objects_to_exclude, deadline);
        EXPECT_EQ(events.size(), 0);
    }
}

} // namespace
