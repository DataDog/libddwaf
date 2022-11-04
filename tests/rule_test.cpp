// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestCondition, Match)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("server.request.query", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets),
        std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::regex_match>(".*", 0, true));

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "server.request.query", ddwaf_object_string(&tmp, "value"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, manifest, true, deadline);
    EXPECT_TRUE(match.has_value());

    EXPECT_STREQ(match->resolved.c_str(), "value");
    EXPECT_STREQ(match->matched.c_str(), "value");
    EXPECT_STREQ(match->operator_name.data(), "match_regex");
    EXPECT_STREQ(match->operator_value.data(), ".*");
    EXPECT_STREQ(match->source.data(), "server.request.query");
    EXPECT_TRUE(match->key_path.empty());
}

TEST(TestCondition, NoMatch)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets),
        std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{}));

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    auto match = cond->match(store, manifest, true, deadline);
    EXPECT_FALSE(match.has_value());
}

TEST(TestRule, Match)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets),
        std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf::rule rule("id", "name", "type", "category",
        std::move(conditions), {"update", "block", "passlist"});

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    rule::cache_type cache;
    auto event = rule.match(store, manifest, cache, deadline);
    EXPECT_TRUE(event.has_value());

    EXPECT_STREQ(event->id.data(), "id");
    EXPECT_STREQ(event->name.data(), "name");
    EXPECT_STREQ(event->type.data(), "type");
    EXPECT_STREQ(event->category.data(), "category");
    std::vector<std::string_view> expected_actions{"update", "block", "passlist"};
    EXPECT_EQ(event->actions, expected_actions);
    EXPECT_EQ(event->matches.size(), 1);

    auto &match = event->matches[0];
    EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
    EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
    EXPECT_STREQ(match.operator_name.data(), "ip_match");
    EXPECT_STREQ(match.operator_value.data(), "");
    EXPECT_STREQ(match.source.data(), "http.client_ip");
    EXPECT_TRUE(match.key_path.empty());
}

TEST(TestRule, NoMatch)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets),
        std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    ddwaf::rule rule("id", "name", "type", "category", std::move(conditions));

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    rule::cache_type cache;
    auto match = rule.match(store, manifest, cache, deadline);
    EXPECT_FALSE(match.has_value());
}

TEST(TestRule, ToggleSingleRule)
{
    auto rule = readFile("toggle_rules.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "id-rule-1", ddwaf_object_bool(&tmp, false));

        EXPECT_EQ(ddwaf_toggle_rules(handle, &root), DDWAF_OK);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value1", ddwaf_object_string(&tmp, "rule1"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestRule, ToggleRuleInCollection)
{
    auto rule = readFile("toggle_rules.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value2", ddwaf_object_string(&tmp, "rule2"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context, &root, &res, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(res,
        {
            .id = "id-rule-2",
            .name = "rule2",
            .type = "flow2",
            .category = "category2",
            .matches = {{
                .op = "match_regex",
                .op_value = "rule2",
                .address = "value2",
                .value = "rule2",
                .highlight = "rule2"
            }}
        });

        ddwaf_result_free(&res);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "id-rule-2", ddwaf_object_bool(&tmp, false));

        EXPECT_EQ(ddwaf_toggle_rules(handle, &root), DDWAF_OK);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value2", ddwaf_object_string(&tmp, "rule2"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context, &root, &res, LONG_TIME), DDWAF_MATCH);
        EXPECT_EVENTS(res,
        {
            .id = "id-rule-3",
            .name = "rule3",
            .type = "flow2",
            .category = "category3",
            .matches = {{
                .op = "match_regex",
                .op_value = "rule2",
                .address = "value2",
                .value = "rule2",
                .highlight = "rule2"
            }}
        });

        ddwaf_result_free(&res);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "id-rule-3", ddwaf_object_bool(&tmp, false));

        EXPECT_EQ(ddwaf_toggle_rules(handle, &root), DDWAF_OK);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value2", ddwaf_object_string(&tmp, "rule2"));

        EXPECT_EQ(ddwaf_run(context, &root, nullptr, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestRule, ToggleNonExistentRules)
{
    auto rule = readFile("toggle_rules.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "id-rule-4", ddwaf_object_bool(&tmp, false));

    EXPECT_EQ(ddwaf_toggle_rules(handle, &root), DDWAF_OK);

    ddwaf_object_free(&root);

    ddwaf_destroy(handle);
}

TEST(TestRule, ToggleWithInvalidObject)
{
    auto rule = readFile("toggle_rules.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_object root, tmp;
        ddwaf_object_array(&root);
        ddwaf_object_array_add(&root, ddwaf_object_bool(&tmp, false));

        EXPECT_EQ(ddwaf_toggle_rules(handle, &root), DDWAF_ERR_INVALID_OBJECT);

        ddwaf_object_free(&root);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "id-rule-1", ddwaf_object_unsigned(&tmp, 5));

        EXPECT_EQ(ddwaf_toggle_rules(handle, &root), DDWAF_ERR_INVALID_OBJECT);

        ddwaf_object_free(&root);
    }

    EXPECT_EQ(ddwaf_toggle_rules(handle, nullptr), DDWAF_ERR_INVALID_ARGUMENT);

    ddwaf_destroy(handle);
}

TEST(TestRule, ToggleWithInvalidHandle)
{
    EXPECT_EQ(ddwaf_toggle_rules(nullptr, nullptr), DDWAF_ERR_INVALID_ARGUMENT);
}
