// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

TEST(TestRule, Match)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};

    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};
    ddwaf::rule rule(
        "id", "name", std::move(tags), std::move(conditions), {"update", "block", "passlist"});

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    rule::cache_type cache;
    auto event = rule.match(store, manifest, cache, {}, deadline);
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

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};
    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};
    ddwaf::rule rule("id", "name", std::move(tags), std::move(conditions));

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    rule::cache_type cache;
    auto match = rule.match(store, manifest, cache, {}, deadline);
    EXPECT_FALSE(match.has_value());
}

TEST(TestRule, ValidateCachedMatch)
{
    ddwaf::manifest_builder mb;
    std::vector<std::shared_ptr<condition>> conditions;

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto manifest = mb.build_manifest();
    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    ddwaf::rule rule("id", "name", std::move(tags), std::move(conditions));
    ddwaf::rule::cache_type cache;

    // To validate that the cache works, we pass an object store containing
    // only the latest address. This ensures that the IP condition can't be
    // matched on the second run.
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto event = rule.match(store, manifest, cache, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto event = rule.match(store, manifest, cache, {}, deadline);
        EXPECT_TRUE(event.has_value());
        EXPECT_STREQ(event->id.data(), "id");
        EXPECT_STREQ(event->name.data(), "name");
        EXPECT_STREQ(event->type.data(), "type");
        EXPECT_STREQ(event->category.data(), "category");
        EXPECT_TRUE(event->actions.empty());
        EXPECT_EQ(event->matches.size(), 2);

        {
            auto &match = event->matches[0];
            EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
            EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
            EXPECT_STREQ(match.operator_name.data(), "ip_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.source.data(), "http.client_ip");
            EXPECT_TRUE(match.key_path.empty());
        }
        {
            auto &match = event->matches[1];
            EXPECT_STREQ(match.resolved.c_str(), "admin");
            EXPECT_STREQ(match.matched.c_str(), "admin");
            EXPECT_STREQ(match.operator_name.data(), "exact_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.source.data(), "usr.id");
            EXPECT_TRUE(match.key_path.empty());
        }
    }
}

TEST(TestRule, MatchWithoutCache)
{
    ddwaf::manifest_builder mb;
    std::vector<std::shared_ptr<condition>> conditions;

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto manifest = mb.build_manifest();
    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    ddwaf::rule rule("id", "name", std::move(tags), std::move(conditions));

    // In this instance we pass a complete store with both addresses but an
    // empty cache on every run to ensure that both conditions are matched on
    // the second run when there isn't a cached match.
    ddwaf::object_store store(manifest);
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        ddwaf::rule::cache_type cache;
        auto event = rule.match(store, manifest, cache, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        store.insert(root);

        ddwaf::timer deadline{2s};
        ddwaf::rule::cache_type cache;
        auto event = rule.match(store, manifest, cache, {}, deadline);
        EXPECT_TRUE(event.has_value());

        {
            auto &match = event->matches[0];
            EXPECT_STREQ(match.resolved.c_str(), "192.168.0.1");
            EXPECT_STREQ(match.matched.c_str(), "192.168.0.1");
            EXPECT_STREQ(match.operator_name.data(), "ip_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.source.data(), "http.client_ip");
            EXPECT_TRUE(match.key_path.empty());
        }
        {
            auto &match = event->matches[1];
            EXPECT_STREQ(match.resolved.c_str(), "admin");
            EXPECT_STREQ(match.matched.c_str(), "admin");
            EXPECT_STREQ(match.operator_name.data(), "exact_match");
            EXPECT_STREQ(match.operator_value.data(), "");
            EXPECT_STREQ(match.source.data(), "usr.id");
            EXPECT_TRUE(match.key_path.empty());
        }
    }
}

TEST(TestRule, NoMatchWithoutCache)
{
    ddwaf::manifest_builder mb;
    std::vector<std::shared_ptr<condition>> conditions;

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto manifest = mb.build_manifest();
    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    ddwaf::rule rule("id", "name", std::move(tags), std::move(conditions));

    // In this test we validate that when the cache is empty and only one
    // address is passed, the filter doesn't match (as it should be).
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};
        ddwaf::rule::cache_type cache;
        auto event = rule.match(store, manifest, cache, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};
        ddwaf::rule::cache_type cache;
        auto event = rule.match(store, manifest, cache, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }
}

TEST(TestRule, FullCachedMatchSecondRun)
{
    ddwaf::manifest_builder mb;
    std::vector<std::shared_ptr<condition>> conditions;

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("http.client_ip", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::ip_match>(
                std::vector<std::string_view>{"192.168.0.1"}));
        conditions.push_back(std::move(cond));
    }

    {
        std::vector<ddwaf::manifest::target_type> targets;
        targets.push_back(mb.insert("usr.id", {}));
        auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
            std::make_unique<rule_processor::exact_match>(std::vector<std::string>{"admin"}));
        conditions.push_back(std::move(cond));
    }

    auto manifest = mb.build_manifest();
    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    ddwaf::rule rule("id", "name", std::move(tags), std::move(conditions));

    // In this test we validate that when a match has already occurred, the
    // second run for the same rule returns no events regardless of input.

    ddwaf::rule::cache_type cache;
    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto event = rule.match(store, manifest, cache, {}, deadline);
        EXPECT_TRUE(event.has_value());
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "admin"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};
        auto event = rule.match(store, manifest, cache, {}, deadline);
        EXPECT_FALSE(event.has_value());
    }
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

    std::unordered_map<std::string, ddwaf::test::event> events = {
        {"id-rule-3", ddwaf::test::event{.id = "id-rule-3",
                          .name = "rule3",
                          .type = "flow2",
                          .category = "category3",
                          .matches = {{.op = "match_regex",
                              .op_value = "rule2",
                              .address = "value2",
                              .value = "rule2",
                              .highlight = "rule2"}}}},
        {"id-rule-2", ddwaf::test::event{.id = "id-rule-2",
                          .name = "rule2",
                          .type = "flow2",
                          .category = "category2",
                          .matches = {{.op = "match_regex",
                              .op_value = "rule2",
                              .address = "value2",
                              .value = "rule2",
                              .highlight = "rule2"}}}}};

    // Due to the use of unordered structures we can't really know which rule
    // will match first as it's implementation dependent, so we keep track of
    // which one matched first.
    std::string first_id;
    std::string second_id;

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "value2", ddwaf_object_string(&tmp, "rule2"));

        ddwaf_result res;
        EXPECT_EQ(ddwaf_run(context, &root, &res, LONG_TIME), DDWAF_MATCH);
        EXPECT_NE(res.data, nullptr);

        if (strstr(res.data, "id-rule-3") != nullptr) {
            first_id = "id-rule-3";
            second_id = "id-rule-2";
        } else {
            first_id = "id-rule-2";
            second_id = "id-rule-3";
        }

        EXPECT_EVENTS(res, events[first_id]);

        ddwaf_result_free(&res);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, first_id.c_str(), ddwaf_object_bool(&tmp, false));

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
        EXPECT_EVENTS(res, events[second_id]);

        ddwaf_result_free(&res);
        ddwaf_context_destroy(context);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, second_id.c_str(), ddwaf_object_bool(&tmp, false));

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

TEST(TestRule, ExcludeObject)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto manifest = mb.build_manifest();

    auto cond = std::make_shared<condition>(std::move(targets), std::vector<PW_TRANSFORM_ID>{},
        std::make_unique<rule_processor::ip_match>(std::vector<std::string_view>{"192.168.0.1"}));

    std::vector<std::shared_ptr<condition>> conditions{std::move(cond)};
    std::unordered_map<std::string, std::string> tags{{"type", "type"}, {"category", "category"}};

    ddwaf::rule rule(
        "id", "name", std::move(tags), std::move(conditions), {"update", "block", "passlist"});

    ddwaf_object root, tmp;
    ddwaf_object_map(&root);
    ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.0.1"));

    ddwaf::object_store store(manifest);
    store.insert(root);

    ddwaf::timer deadline{2s};

    rule::cache_type cache;
    auto event = rule.match(store, manifest, cache, {&root.array[0]}, deadline);
    EXPECT_FALSE(event.has_value());
}
