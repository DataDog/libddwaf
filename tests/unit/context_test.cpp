// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "action_mapper.hpp"
#include "common/gtest_utils.hpp"
#include "context.hpp"
#include "exception.hpp"
#include "exclusion/input_filter.hpp"
#include "exclusion/rule_filter.hpp"
#include "expression.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"

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

/*TEST(TestContext, PreprocessorEval)*/
/*{*/
/*test::expression_builder builder(1);*/
/*builder.start_condition();*/
/*builder.add_argument();*/
/*builder.add_target("http.client_ip");*/
/*builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});*/

/*std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};*/

/*auto rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());*/
/*auto proc = std::make_shared<mock::processor>();*/

/*Sequence seq;*/

/*EXPECT_CALL(*proc, eval(_, _, _, _)).InSequence(seq);*/
/*EXPECT_CALL(*rule, match(_, _, _, _, _)).InSequence(seq).WillOnce(Return(std::nullopt));*/

/*auto ruleset = test::get_default_ruleset();*/
/*ruleset->insert_rules({rule}, {});*/
/*ruleset->preprocessors.emplace("id", proc);*/

/*ddwaf::context ctx(rbuilder.build());*/

/*ddwaf_object root;*/
/*ddwaf_object tmp;*/
/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));*/

/*ctx.run(root, std::nullopt, std::nullopt, 20000);*/
/*}*/

/*TEST(TestContext, PostprocessorEval)*/
/*{*/
/*test::expression_builder builder(1);*/
/*builder.start_condition();*/
/*builder.add_argument();*/
/*builder.add_target("http.client_ip");*/
/*builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});*/

/*std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};*/

/*auto rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());*/
/*auto proc = std::make_shared<mock::processor>();*/

/*Sequence seq;*/

/*EXPECT_CALL(*rule, match(_, _, _, _, _)).InSequence(seq).WillOnce(Return(std::nullopt));*/
/*EXPECT_CALL(*proc, eval(_, _, _, _)).InSequence(seq);*/

/*auto ruleset = test::get_default_ruleset();*/
/*ruleset->insert_rules({rule}, {});*/
/*ruleset->postprocessors.emplace("id", proc);*/

/*ddwaf::context ctx(rbuilder.build());*/

/*ddwaf_object root;*/
/*ddwaf_object tmp;*/
/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));*/

/*ctx.run(root, std::nullopt, std::nullopt, 20000);*/
/*}*/

/*TEST(TestContext, SkipRuleNoTargets)*/
/*{*/
/*test::expression_builder builder(1);*/
/*builder.start_condition();*/
/*builder.add_argument();*/
/*builder.add_target("http.client_ip");*/
/*builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});*/

/*std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};*/

/*auto rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());*/

/*auto ruleset = test::get_default_ruleset();*/
/*ruleset->insert_rules({rule}, {});*/

/*EXPECT_CALL(*rule, match(_, _, _, _, _)).Times(0);*/

/*ddwaf::context ctx(rbuilder.build());*/

/*ddwaf_object root;*/
/*ddwaf_object tmp;*/
/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(&root, "client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));*/

/*ctx.run(root, std::nullopt, std::nullopt, 20000);*/
/*}*/

TEST(TestContext, MatchTimeout)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder;
    rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    ddwaf::timer deadline{0s};
    ddwaf::test::context ctx(rbuilder.build());

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    EXPECT_THROW(ctx.eval_rules({}, deadline), ddwaf::timeout_exception);
}

TEST(TestContext, NoMatch)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder;
    rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

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
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder;
    rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

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
    test::ruleset_builder rbuilder;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build()});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.eval_rules({}, deadline);
    EXPECT_EQ(events.size(), 1);

    auto &event = events[0];
    EXPECT_STRV(event.rule->get_id(), "id1");
    EXPECT_STRV(event.rule->get_name(), "name1");
    EXPECT_STRV(event.rule->get_tag("type"), "type");
    EXPECT_STRV(event.rule->get_tag("category"), "category1");
    std::vector<std::string> expected_actions{};
    EXPECT_EQ(event.rule->get_actions(), expected_actions);
    EXPECT_EQ(event.matches.size(), 1);

    auto &match = event.matches[0];
    EXPECT_STREQ(match.args[0].resolved.c_str(), "192.168.0.1");
    EXPECT_STREQ(match.highlights[0].c_str(), "192.168.0.1");
    EXPECT_STRV(match.operator_name, "ip_match");
    EXPECT_STRV(match.operator_value, "");
    EXPECT_STRV(match.args[0].address, "http.client_ip");
    EXPECT_TRUE(match.args[0].key_path.empty());
}

TEST(TestContext, MatchMultipleRulesWithPrioritySingleRun)
{
    test::ruleset_builder rbuilder;
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block});
    }

    auto ruleset = rbuilder.build();
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
        EXPECT_STRV(event.rule->get_id(), "id2");
        EXPECT_EQ(event.rule->get_actions().size(), 1);
        EXPECT_STRV(event.rule->get_actions()[0], "block");
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
        EXPECT_STRV(event.rule->get_id(), "id2");
        EXPECT_EQ(event.rule->get_actions().size(), 1);
        EXPECT_STRV(event.rule->get_actions()[0], "block");
    }
}

TEST(TestContext, MatchMultipleRulesInCollectionDoubleRun)
{
    test::ruleset_builder rbuilder;
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build()});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STRV(event.rule->get_id(), "id1");
        EXPECT_STRV(event.rule->get_name(), "name1");
        EXPECT_STRV(event.rule->get_tag("type"), "type");
        EXPECT_STRV(event.rule->get_tag("category"), "category1");
        std::vector<std::string> expected_actions{};
        EXPECT_EQ(event.rule->get_actions(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.args[0].resolved.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.highlights[0].c_str(), "192.168.0.1");
        EXPECT_STRV(match.operator_name, "ip_match");
        EXPECT_STRV(match.operator_value, "");
        EXPECT_STRV(match.args[0].address, "http.client_ip");
        EXPECT_TRUE(match.args[0].key_path.empty());
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
    test::ruleset_builder rbuilder;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STRV(event.rule->get_id(), "id1");
        EXPECT_STRV(event.rule->get_name(), "name1");
        EXPECT_STRV(event.rule->get_tag("type"), "type");
        EXPECT_STRV(event.rule->get_tag("category"), "category1");
        std::vector<std::string> expected_actions{};
        EXPECT_EQ(event.rule->get_actions(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.args[0].resolved.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.highlights[0].c_str(), "192.168.0.1");
        EXPECT_STRV(match.operator_name, "ip_match");
        EXPECT_STRV(match.operator_value, "");
        EXPECT_STRV(match.args[0].address, "http.client_ip");
        EXPECT_TRUE(match.args[0].key_path.empty());
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
        EXPECT_STRV(event.rule->get_id(), "id2");
        EXPECT_STRV(event.rule->get_name(), "name2");
        EXPECT_STRV(event.rule->get_tag("type"), "type");
        EXPECT_STRV(event.rule->get_tag("category"), "category2");
        std::vector<std::string> expected_actions{"block"};
        EXPECT_EQ(event.rule->get_actions(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.args[0].resolved.c_str(), "admin");
        EXPECT_STREQ(match.highlights[0].c_str(), "admin");
        EXPECT_STRV(match.operator_name, "exact_match");
        EXPECT_STRV(match.operator_value, "");
        EXPECT_STRV(match.args[0].address, "usr.id");
        EXPECT_TRUE(match.args[0].key_path.empty());
    }
}

TEST(TestContext, MatchMultipleRulesWithPriorityDoubleRunPriorityFirst)
{
    test::ruleset_builder rbuilder;
    auto ruleset = test::get_default_ruleset();
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build()});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto events = ctx.eval_rules({}, deadline);
        EXPECT_EQ(events.size(), 1);

        auto &event = events[0];
        EXPECT_STRV(event.rule->get_id(), "id1");
        EXPECT_STRV(event.rule->get_name(), "name1");
        EXPECT_STRV(event.rule->get_tag("type"), "type");
        EXPECT_STRV(event.rule->get_tag("category"), "category1");
        std::vector<std::string> expected_actions{"block"};
        EXPECT_EQ(event.rule->get_actions(), expected_actions);
        EXPECT_EQ(event.matches.size(), 1);

        auto &match = event.matches[0];
        EXPECT_STREQ(match.args[0].resolved.c_str(), "192.168.0.1");
        EXPECT_STREQ(match.highlights[0].c_str(), "192.168.0.1");
        EXPECT_STRV(match.operator_name, "ip_match");
        EXPECT_STRV(match.operator_value, "");
        EXPECT_STRV(match.args[0].address, "http.client_ip");
        EXPECT_TRUE(match.args[0].key_path.empty());
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

TEST(TestContext, MatchMultipleCollectionsSingleRun)
{
    test::ruleset_builder rbuilder;
    auto ruleset = test::get_default_ruleset();
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build()});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.eval_rules({}, deadline);
    EXPECT_EQ(events.size(), 2);
}

TEST(TestContext, MatchPriorityCollectionsSingleRun)
{
    test::ruleset_builder rbuilder;
    auto ruleset = test::get_default_ruleset();
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build(),
            std::vector<std::string>{"redirect"}});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ctx.insert(root);

    auto events = ctx.eval_rules({}, deadline);
    EXPECT_EQ(events.size(), 1);
}

TEST(TestContext, MatchMultipleCollectionsDoubleRun)
{
    test::ruleset_builder rbuilder;
    auto ruleset = test::get_default_ruleset();
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build()});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

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
    test::ruleset_builder rbuilder;
    auto ruleset = test::get_default_ruleset();
    std::vector<std::shared_ptr<core_rule>> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type1"}, {"category", "category1"}};

        rbuilder.insert_base_rule(core_rule{"id1", "name1", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type2"}, {"category", "category2"}};

        rbuilder.insert_base_rule(core_rule{"id2", "name2", std::move(tags), builder.build(),
            std::vector<std::string>{"redirect"}});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

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

/*TEST(TestContext, SkipRuleFilterNoTargets)*/
/*{*/
// test::ruleset_builder rbuilder;
/*auto ruleset = test::get_default_ruleset();*/

/*// Generate rule*/
/*std::shared_ptr<mock::rule> rule;*/
/*std::shared_ptr<mock::rule_filter> filter;*/
/*{*/
/*test::expression_builder builder(1);*/
/*builder.start_condition();*/
/*builder.add_argument();*/
/*builder.add_target("usr.id");*/
/*builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});*/

/*std::unordered_map<std::string, std::string> tags{*/
/*{"type", "type"}, {"category", "category"}};*/

/*rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());*/

/*ruleset->insert_rules({rule}, {});*/
/*}*/

/*// Generate filter*/
/*{*/
/*test::expression_builder builder(1);*/
/*builder.start_condition();*/
/*builder.add_argument();*/
/*builder.add_target("http.client_ip");*/
/*builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});*/

/*filter = std::make_shared<mock::rule_filter>(*/
/*"1", builder.build(), std::set<core_rule *>{rule.get()});*/

/*ruleset->insert_filter<exclusion::rule_filter>(filter);*/
/*}*/

/*EXPECT_CALL(*rule, match(_, _, _, _, _)).Times(0);*/
/*EXPECT_CALL(*filter, match(_, _, _, _)).Times(0);*/

/*ddwaf_object root;*/
/*ddwaf_object tmp;*/
/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(&root, "user_name", ddwaf_object_string(&tmp, "admin"));*/
/*ddwaf_object_map_add(&root, "client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));*/

/*ddwaf::context ctx(rbuilder.build());*/
/*ctx.run(root, std::nullopt, std::nullopt, 20000);*/
/*}*/

/*TEST(TestContext, SkipRuleButNotRuleFilterNoTargets)*/
/*{*/
// test::ruleset_builder rbuilder;
/*auto ruleset = test::get_default_ruleset();*/

/*// Generate rule*/
/*std::shared_ptr<mock::rule> rule;*/
/*std::shared_ptr<mock::rule_filter> filter;*/
/*{*/
/*test::expression_builder builder(1);*/
/*builder.start_condition();*/
/*builder.add_argument();*/
/*builder.add_target("usr.id");*/
/*builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});*/

/*std::unordered_map<std::string, std::string> tags{*/
/*{"type", "type"}, {"category", "category"}};*/

/*rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());*/

/*ruleset->insert_rules({rule}, {});*/
/*}*/

/*// Generate filter*/
/*{*/
/*test::expression_builder builder(1);*/
/*builder.start_condition();*/
/*builder.add_argument();*/
/*builder.add_target("http.client_ip");*/
/*builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});*/

/*filter = std::make_shared<mock::rule_filter>(*/
/*"1", builder.build(), std::set<core_rule *>{rule.get()});*/

/*ruleset->insert_filter<exclusion::rule_filter>(filter);*/
/*}*/

/*EXPECT_CALL(*rule, match(_, _, _, _, _)).Times(0);*/
/*EXPECT_CALL(*filter, match(_, _, _, _)).WillOnce(Return(std::nullopt));*/

/*ddwaf_object root;*/
/*ddwaf_object tmp;*/
/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(&root, "user_name", ddwaf_object_string(&tmp, "admin"));*/
/*ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));*/

/*ddwaf::context ctx(rbuilder.build());*/
/*ctx.run(root, std::nullopt, std::nullopt, 20000);*/
/*}*/

TEST(TestContext, RuleFilterWithCondition)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{"1", builder.build(), std::set<core_rule *>{rule}});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root);

    auto rules_to_exclude = ctx.eval_filters(deadline);
    EXPECT_EQ(rules_to_exclude.size(), 1);
    EXPECT_TRUE(rules_to_exclude.contains(rule));

    auto events = ctx.eval_rules(rules_to_exclude, deadline);
    EXPECT_EQ(events.size(), 0);
}

TEST(TestContext, RuleFilterWithEphemeralConditionMatch)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{"1", builder.build(), std::set<core_rule *>{rule}});
    }

    ddwaf::test::context ctx(rbuilder.build());

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
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{"1", builder.build(), std::set<core_rule *>{rule}});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.route");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"unrouted"});

        rbuilder.insert_filter(rule_filter{
            "2", builder.build(), std::set<core_rule *>{rule}, exclusion::filter_mode::monitor});
    }

    ddwaf::test::context ctx(rbuilder.build());

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
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build(),
            std::vector<std::string>{"block"}, true, core_rule::source_type::base,
            core_rule::verdict_type::block});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{
            "1", builder.build(), std::set<core_rule *>{rule}, exclusion::filter_mode::monitor});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.route");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"unrouted"});

        rbuilder.insert_filter(rule_filter{"2", builder.build(), std::set<core_rule *>{rule}});
    }

    ddwaf::test::context ctx(rbuilder.build());

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
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{"1", builder.build(), std::set<core_rule *>{rule}});
    }

    ddwaf::timer deadline{0s};
    ddwaf::test::context ctx(rbuilder.build());

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
    test::ruleset_builder rbuilder;

    // Generate rule
    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    // Generate filter
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{"1", builder.build(), std::set<core_rule *>{rule}});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

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
    test::ruleset_builder rbuilder;

    // Generate rule
    constexpr unsigned num_rules = 9;
    std::vector<core_rule *> rules;
    rules.resize(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules[i] = rbuilder.insert_base_rule(core_rule{"id" + std::to_string(i), "name",
            std::move(tags), std::make_shared<expression>(), std::vector<std::string>{}});
    }

    ddwaf::timer deadline{2s};

    {
        ddwaf::test::context ctx(rbuilder.build());
        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 0);
    }

    {
        rbuilder.insert_filter(rule_filter{"1", std::make_shared<expression>(),
            std::set<core_rule *>{rules[0], rules[1], rules[2]}});
        ddwaf::test::context ctx(rbuilder.build());

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 3);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
    }

    {
        rbuilder.insert_filter(rule_filter{"2", std::make_shared<expression>(),
            std::set<core_rule *>{rules[3], rules[4], rules[5]}});
        ddwaf::test::context ctx(rbuilder.build());

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 6);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
    }

    {
        rbuilder.insert_filter(rule_filter{"3", std::make_shared<expression>(),
            std::set<core_rule *>{rules[6], rules[7], rules[8]}});
        ddwaf::test::context ctx(rbuilder.build());

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
    }
}

TEST(TestContext, MultipleRuleFiltersOverlappingRules)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    constexpr unsigned num_rules = 9;
    std::vector<core_rule *> rules;
    rules.resize(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules[i] = rbuilder.insert_base_rule(core_rule{id, "name", std::move(tags),
            std::make_shared<expression>(), std::vector<std::string>{}});
    }

    ddwaf::timer deadline{2s};

    {
        ddwaf::test::context ctx(rbuilder.build());
        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 0);
    }

    {
        rbuilder.insert_filter(rule_filter{"1", std::make_shared<expression>(),
            std::set<core_rule *>{rules[0], rules[1], rules[2], rules[3]}});
        ddwaf::test::context ctx(rbuilder.build());

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 4);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
    }

    {
        rbuilder.insert_filter(rule_filter{"2", std::make_shared<expression>(),
            std::set<core_rule *>{rules[2], rules[3], rules[4]}});
        ddwaf::test::context ctx(rbuilder.build());

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 5);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
    }

    {
        rbuilder.insert_filter(rule_filter{"3", std::make_shared<expression>(),
            std::set<core_rule *>{rules[0], rules[5], rules[6]}});
        ddwaf::test::context ctx(rbuilder.build());

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 7);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
    }

    {
        rbuilder.insert_filter(rule_filter{"4", std::make_shared<expression>(),
            std::set<core_rule *>{rules[7], rules[8], rules[6]}});
        ddwaf::test::context ctx(rbuilder.build());

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
    }

    {
        rbuilder.insert_filter(rule_filter{"5", std::make_shared<expression>(),
            std::set<core_rule *>{rules[0], rules[1], rules[2], rules[3], rules[4], rules[5],
                rules[6], rules[7], rules[8]}});
        ddwaf::test::context ctx(rbuilder.build());

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 9);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
    }
}

TEST(TestContext, MultipleRuleFiltersNonOverlappingRulesWithConditions)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    constexpr unsigned num_rules = 10;
    std::vector<core_rule *> rules;
    rules.resize(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules[i] = rbuilder.insert_base_rule(core_rule{std::string(id), "name", std::move(tags),
            std::make_shared<expression>(), std::vector<std::string>{}});
    }
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{"1", builder.build(),
            std::set<core_rule *>{rules[0], rules[1], rules[2], rules[3], rules[4]}});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        rbuilder.insert_filter(rule_filter{"2", builder.build(),
            std::set<core_rule *>{rules[5], rules[6], rules[7], rules[8], rules[9]}});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 5);
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[9]));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 10);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[9]));
    }
}

TEST(TestContext, MultipleRuleFiltersOverlappingRulesWithConditions)
{
    test::ruleset_builder rbuilder;

    // Generate rule
    constexpr unsigned num_rules = 10;
    std::vector<core_rule *> rules;
    rules.resize(num_rules);
    for (unsigned i = 0; i < num_rules; i++) {
        std::string id = "id" + std::to_string(i);

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rules[i] = rbuilder.insert_base_rule(core_rule{std::string(id), "name", std::move(tags),
            std::make_shared<expression>(), std::vector<std::string>{}});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        rbuilder.insert_filter(rule_filter{"1", builder.build(),
            std::set<core_rule *>{
                rules[0], rules[1], rules[2], rules[3], rules[4], rules[5], rules[6]}});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        rbuilder.insert_filter(rule_filter{"2", builder.build(),
            std::set<core_rule *>{
                rules[3], rules[4], rules[5], rules[6], rules[7], rules[8], rules[9]}});
    }

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 7);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);

        auto rules_to_exclude = ctx.eval_filters(deadline);
        EXPECT_EQ(rules_to_exclude.size(), 10);
        EXPECT_TRUE(rules_to_exclude.contains(rules[0]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[1]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[2]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[3]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[4]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[5]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[6]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[7]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[8]));
        EXPECT_TRUE(rules_to_exclude.contains(rules[9]));
    }
}

/*TEST(TestContext, SkipInputFilterNoTargets)*/
/*{*/
/*test::ruleset_builder rbuilder;*/
/*auto ruleset = test::get_default_ruleset();*/

/*// Generate rule*/
/*std::shared_ptr<mock::rule> rule;*/
/*std::shared_ptr<mock::input_filter> filter;*/
/*{*/
/*test::expression_builder builder(1);*/
/*builder.start_condition();*/
/*builder.add_argument();*/
/*builder.add_target("usr.id");*/
/*builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});*/

/*std::unordered_map<std::string, std::string> tags{*/
/*{"type", "type"}, {"category", "category"}};*/

/*rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());*/

/*ruleset->insert_rules({rule}, {});*/
/*}*/

/*// Generate filter*/
/*{*/
/*auto obj_filter = std::make_shared<object_filter>();*/
/*obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");*/

/*std::set<core_rule *> eval_filters{rule.get()};*/
/*filter = std::make_shared<mock::input_filter>(*/
/*"1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));*/
/*ruleset->insert_filter<exclusion::input_filter>(filter);*/
/*}*/

/*EXPECT_CALL(*rule, match(_, _, _, _, _)).Times(0);*/
/*EXPECT_CALL(*filter, match(_, _, _, _)).Times(0);*/

/*ddwaf_object root;*/
/*ddwaf_object tmp;*/
/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(&root, "user_name", ddwaf_object_string(&tmp, "admin"));*/
/*ddwaf_object_map_add(&root, "client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));*/

/*ddwaf::context ctx(rbuilder.build());*/
/*ctx.run(root, std::nullopt, std::nullopt, 20000);*/
/*}*/

/*TEST(TestContext, SkipRuleButNotInputFilterNoTargets)*/
/*{*/
/*auto ruleset = test::get_default_ruleset();*/

/*// Generate rule*/
/*std::shared_ptr<mock::rule> rule;*/
/*std::shared_ptr<mock::input_filter> filter;*/
/*{*/
/*test::expression_builder builder(1);*/
/*builder.start_condition();*/
/*builder.add_argument();*/
/*builder.add_target("usr.id");*/
/*builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});*/

/*std::unordered_map<std::string, std::string> tags{*/
/*{"type", "type"}, {"category", "category"}};*/

/*rule = std::make_shared<mock::rule>("id", "name", std::move(tags), builder.build());*/

/*ruleset->insert_rules({rule}, {});*/
/*}*/

/*// Generate filter*/
/*{*/
/*auto obj_filter = std::make_shared<object_filter>();*/
/*obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");*/

/*std::set<core_rule *> eval_filters{rule.get()};*/
/*filter = std::make_shared<mock::input_filter>(*/
/*"1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter));*/
/*ruleset->insert_filter<exclusion::input_filter>(filter);*/
/*}*/

/*EXPECT_CALL(*rule, match(_, _, _, _, _)).Times(0);*/
/*EXPECT_CALL(*filter, match(_, _, _, _)).WillOnce(Return(std::nullopt));*/

/*ddwaf_object root;*/
/*ddwaf_object tmp;*/
/*ddwaf_object_map(&root);*/
/*ddwaf_object_map_add(&root, "user_name", ddwaf_object_string(&tmp, "admin"));*/
/*ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));*/

/*ddwaf::context ctx(rbuilder.build());*/
/*ctx.run(root, std::nullopt, std::nullopt, 20000);*/
/*}*/

TEST(TestContext, InputFilterExclude)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder;
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

    rbuilder.insert_filter(input_filter{
        "1", std::make_shared<expression>(), std::set<core_rule *>{rule}, std::move(obj_filter)});

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

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
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.add_target("http.peer_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder;
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

    rbuilder.insert_filter(input_filter{
        "1", std::make_shared<expression>(), std::set<core_rule *>{rule}, std::move(obj_filter)});

    ddwaf::test::context ctx(rbuilder.build());

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
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.add_target("http.peer_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{nullptr};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

    rbuilder.insert_filter(input_filter{
        "1", std::make_shared<expression>(), std::set<core_rule *>{rule}, std::move(obj_filter)});

    ddwaf::test::context ctx(rbuilder.build());

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
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    rbuilder.insert_filter(input_filter{
        "1", std::make_shared<expression>(), std::set<core_rule *>{rule}, std::move(obj_filter)});
    rbuilder.insert_filter(
        rule_filter{"1", std::make_shared<expression>(), std::set<core_rule *>{rule}});

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

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

    auto it = objects_to_exclude.persistent.find(rule);
    it->second.mode = filter_mode::none;
    EXPECT_TRUE(it->second.objects.empty());

    auto events = ctx.eval_rules(objects_to_exclude, deadline);
    EXPECT_EQ(events.size(), 1);
}

TEST(TestContext, InputFilterExcludeRuleEphemeral)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    rbuilder.insert_filter(input_filter{
        "1", std::make_shared<expression>(), std::set<core_rule *>{rule}, std::move(obj_filter)});
    rbuilder.insert_filter(
        rule_filter{"1", std::make_shared<expression>(), std::set<core_rule *>{rule}});

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root, attribute::ephemeral);

    auto objects_to_exclude = ctx.eval_filters(deadline);
    EXPECT_EQ(objects_to_exclude.size(), 1);

    auto it = objects_to_exclude.persistent.find(rule);
    EXPECT_TRUE(it->second.objects.empty());

    EXPECT_FALSE(objects_to_exclude.ephemeral.contains(rule));
}

TEST(TestContext, InputFilterMonitorRuleEphemeral)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    rbuilder.insert_filter(input_filter{
        "1", std::make_shared<expression>(), std::set<core_rule *>{rule}, std::move(obj_filter)});
    rbuilder.insert_filter(rule_filter{
        "1", std::make_shared<expression>(), std::set<core_rule *>{rule}, filter_mode::monitor});

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    ddwaf_object root;
    ddwaf_object tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
    ctx.insert(root, attribute::ephemeral);

    auto objects_to_exclude = ctx.eval_filters(deadline);
    EXPECT_EQ(objects_to_exclude.size(), 2);

    {
        auto it = objects_to_exclude.persistent.find(rule);
        EXPECT_TRUE(it->second.objects.empty());
    }

    {
        auto it = objects_to_exclude.ephemeral.find(rule);
        EXPECT_FALSE(it->second.objects.empty());
    }
}

TEST(TestContext, InputFilterExcluderRuleEphemeralAndPersistent)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    obj_filter->insert(get_target_index("usr.id"), "usr.id");
    rbuilder.insert_filter(input_filter{
        "1", std::make_shared<expression>(), std::set<core_rule *>{rule}, std::move(obj_filter)});
    rbuilder.insert_filter(
        rule_filter{"1", std::make_shared<expression>(), std::set<core_rule *>{rule}});

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root, attribute::ephemeral);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);
    }

    auto objects_to_exclude = ctx.eval_filters(deadline);
    EXPECT_EQ(objects_to_exclude.size(), 1);

    auto it = objects_to_exclude.persistent.find(rule);
    EXPECT_TRUE(it->second.objects.empty());

    EXPECT_FALSE(objects_to_exclude.ephemeral.contains(rule));
}

TEST(TestContext, InputFilterMonitorRuleEphemeralAndPersistent)
{
    test::expression_builder builder(1);
    builder.start_condition();
    builder.add_argument();
    builder.add_target("http.client_ip");
    builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    test::ruleset_builder rbuilder{};
    auto *rule =
        rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});

    auto obj_filter = std::make_shared<object_filter>();
    obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
    obj_filter->insert(get_target_index("usr.id"), "usr.id");
    rbuilder.insert_filter(input_filter{
        "1", std::make_shared<expression>(), std::set<core_rule *>{rule}, std::move(obj_filter)});
    rbuilder.insert_filter(rule_filter{
        "1", std::make_shared<expression>(), std::set<core_rule *>{rule}, filter_mode::monitor});

    ddwaf::timer deadline{2s};
    ddwaf::test::context ctx(rbuilder.build());

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ctx.insert(root, attribute::ephemeral);
    }

    {
        ddwaf_object root;
        ddwaf_object tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));
        ctx.insert(root);
    }

    auto objects_to_exclude = ctx.eval_filters(deadline);
    EXPECT_EQ(objects_to_exclude.size(), 2);

    {
        auto it = objects_to_exclude.persistent.find(rule);
        EXPECT_FALSE(it->second.objects.empty());
    }

    {
        auto it = objects_to_exclude.ephemeral.find(rule);
        EXPECT_FALSE(it->second.objects.empty());
    }
}

TEST(TestContext, InputFilterWithCondition)
{
    test::ruleset_builder rbuilder{};

    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<core_rule *> eval_filters{rule};
        rbuilder.insert_filter(
            input_filter{"1", builder.build(), std::move(eval_filters), std::move(obj_filter)});
    }

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
    test::ruleset_builder rbuilder{};

    core_rule *rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "type"}, {"category", "category"}};

        rule = rbuilder.insert_base_rule(core_rule{"id", "name", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<core_rule *> eval_filters{rule};
        rbuilder.insert_filter(
            input_filter{"1", builder.build(), std::move(eval_filters), std::move(obj_filter)});
    }

    ddwaf::test::context ctx(rbuilder.build());
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
    test::ruleset_builder rbuilder{};
    std::vector<core_rule *> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        rules.emplace_back(rbuilder.insert_base_rule(
            core_rule{"ip_id", "name", std::move(tags), builder.build()}));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr.id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        rules.emplace_back(rbuilder.insert_base_rule(
            core_rule{"usr_id", "name", std::move(tags), builder.build()}));
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
        obj_filter->insert(get_target_index("usr.id"), "usr.id");

        rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
            std::set<core_rule *>{rules[0], rules[1]}, std::move(obj_filter)});
    }

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
    test::ruleset_builder rbuilder{};
    std::vector<core_rule *> rules;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        rules.emplace_back(rbuilder.insert_base_rule(
            core_rule{"ip_id", "name", std::move(tags), builder.build()}));
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr_id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        rules.emplace_back(rbuilder.insert_base_rule(
            core_rule{"usr_id", "name", std::move(tags), builder.build()}));
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        rbuilder.insert_filter(input_filter{"1", std::make_shared<expression>(),
            std::set<core_rule *>{rules[0]}, std::move(obj_filter)});
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("usr.id"), "usr.id");

        rbuilder.insert_filter(input_filter{"2", std::make_shared<expression>(),
            std::set<core_rule *>{rules[1]}, std::move(obj_filter)});
    }

    // Without usr.id, nothing should be excluded
    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
    test::ruleset_builder rbuilder{};

    core_rule *ip_rule, *usr_rule, *cookie_rule;
    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("http.client_ip");
        builder.end_condition<matcher::ip_match>(std::vector<std::string_view>{"192.168.0.1"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "ip_type"}, {"category", "category"}};

        ip_rule =
            rbuilder.insert_base_rule(core_rule{"ip_id", "name", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("usr_id");
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"admin"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "usr_type"}, {"category", "category"}};

        usr_rule = rbuilder.insert_base_rule(
            core_rule{"usr_id", "name", std::move(tags), builder.build()});
    }

    {
        test::expression_builder builder(1);
        builder.start_condition();
        builder.add_argument();
        builder.add_target("server.request.headers", {"cookie"});
        builder.end_condition<matcher::exact_match>(std::vector<std::string>{"mycookie"});

        std::unordered_map<std::string, std::string> tags{
            {"type", "cookie_type"}, {"category", "category"}};

        cookie_rule = rbuilder.insert_base_rule(
            core_rule{"cookie_id", "name", std::move(tags), builder.build()});
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");
        obj_filter->insert(get_target_index("server.request.headers"), "server.request.headers");

        std::set<core_rule *> eval_filters{ip_rule, cookie_rule};
        rbuilder.insert_filter(input_filter{
            "1", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter)});
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("usr.id"), "usr.id");
        obj_filter->insert(get_target_index("http.client_ip"), "http.client_ip");

        std::set<core_rule *> eval_filters{usr_rule, ip_rule};
        rbuilder.insert_filter(input_filter{
            "2", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter)});
    }

    {
        auto obj_filter = std::make_shared<object_filter>();
        obj_filter->insert(get_target_index("usr.id"), "usr.id");
        obj_filter->insert(get_target_index("server.request.headers"), "server.request.headers");

        std::set<core_rule *> eval_filters{usr_rule, cookie_rule};
        rbuilder.insert_filter(input_filter{
            "3", std::make_shared<expression>(), std::move(eval_filters), std::move(obj_filter)});
    }

    {
        ddwaf::timer deadline{2s};
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
        ddwaf::test::context ctx(rbuilder.build());

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
