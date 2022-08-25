// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "test.h"

using namespace ddwaf;

namespace ddwaf
{
namespace rule_processor
{
class mock_processor : public base
{
public:
    using rule_data_type = std::vector<std::string_view>;

    mock_processor() = default;
    explicit mock_processor(const rule_data_type &list) {(void)list;}
    ~mock_processor() override = default;

    std::string_view name() const override { return "mock_processor"; }

    std::optional<event::match> match(std::string_view str) const override {
        (void)str;
        return {};
    }
};

}
namespace parser
{

using data_type = std::vector<std::string_view>;

template <>
data_type parse_rule_data<data_type>(std::string_view type, parameter &input)
{
    (void)type;
    return input;
}

}

}

TEST(TestRuleDataDispatcher, InterfaceNullHandle)
{
    EXPECT_EQ(ddwaf_update_rule_data(nullptr, nullptr), DDWAF_ERR_INVALID_ARGUMENT);
}

TEST(TestRuleDataDispatcher, InterfaceNullObject)
{
    auto rule = readFile("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    EXPECT_EQ(ddwaf_update_rule_data(handle, nullptr), DDWAF_ERR_INVALID_ARGUMENT);
    ddwaf_destroy(handle);
}

TEST(TestRuleDataDispatcher, InterfaceInvalidObject)
{
    auto rule = readFile("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_object root;
    ddwaf_object_map(&root);
    EXPECT_EQ(ddwaf_update_rule_data(handle, &root), DDWAF_ERR_INVALID_OBJECT);
    ddwaf_object_free(&root);

    ddwaf_destroy(handle);
}

TEST(TestRuleDataDispatcher, Interface)
{
    auto rule = readFile("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "paco"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_object root, ips, user, data, data_point, tmp;

        ddwaf_object_map(&data_point);
        ddwaf_object_map_add(&data_point, "value", ddwaf_object_string(&tmp, "192.168.1.1"));
        ddwaf_object_map_add(&data_point, "expiration", ddwaf_object_string(&tmp, "0"));

        ddwaf_object_array(&data);
        ddwaf_object_array_add(&data, &data_point);

        ddwaf_object_map(&ips);
        ddwaf_object_map_add(&ips, "type", ddwaf_object_string(&tmp, "ip_with_expiration"));
        ddwaf_object_map_add(&ips, "id", ddwaf_object_string(&tmp, "ip_data"));
        ddwaf_object_map_add(&ips, "data", &data);


        ddwaf_object_map(&data_point);
        ddwaf_object_map_add(&data_point, "value", ddwaf_object_string(&tmp, "paco"));
        ddwaf_object_map_add(&data_point, "expiration", ddwaf_object_string(&tmp, "0"));

        ddwaf_object_array(&data);
        ddwaf_object_array_add(&data, &data_point);

        ddwaf_object_map(&user);
        ddwaf_object_map_add(&user, "type", ddwaf_object_string(&tmp, "data_with_expiration"));
        ddwaf_object_map_add(&user, "id", ddwaf_object_string(&tmp, "usr_data"));
        ddwaf_object_map_add(&user, "data", &data);

        ddwaf_object_array(&root);
        ddwaf_object_array_add(&root, &ips);
        ddwaf_object_array_add(&root, &user);

        EXPECT_EQ(ddwaf_update_rule_data(handle, &root), DDWAF_OK);
        ddwaf_object_free(&root);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "paco"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestRuleDataDispatcher, InterfacePreloadData)
{
    auto rule = readFile("rule_data_with_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "paco"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_object root, ips, user, data, data_point, tmp;

        ddwaf_object_map(&data_point);
        ddwaf_object_map_add(&data_point, "value", ddwaf_object_string(&tmp, "192.168.1.2"));
        ddwaf_object_map_add(&data_point, "expiration", ddwaf_object_string(&tmp, "0"));

        ddwaf_object_array(&data);
        ddwaf_object_array_add(&data, &data_point);

        ddwaf_object_map(&ips);
        ddwaf_object_map_add(&ips, "type", ddwaf_object_string(&tmp, "ip_with_expiration"));
        ddwaf_object_map_add(&ips, "id", ddwaf_object_string(&tmp, "ip_data"));
        ddwaf_object_map_add(&ips, "data", &data);


        ddwaf_object_map(&data_point);
        ddwaf_object_map_add(&data_point, "value", ddwaf_object_string(&tmp, "pepe"));
        ddwaf_object_map_add(&data_point, "expiration", ddwaf_object_string(&tmp, "0"));

        ddwaf_object_array(&data);
        ddwaf_object_array_add(&data, &data_point);

        ddwaf_object_map(&user);
        ddwaf_object_map_add(&user, "type", ddwaf_object_string(&tmp, "data_with_expiration"));
        ddwaf_object_map_add(&user, "id", ddwaf_object_string(&tmp, "usr_data"));
        ddwaf_object_map_add(&user, "data", &data);

        ddwaf_object_array(&root);
        ddwaf_object_array_add(&root, &ips);
        ddwaf_object_array_add(&root, &user);

        EXPECT_EQ(ddwaf_update_rule_data(handle, &root), DDWAF_OK);
        ddwaf_object_free(&root);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "paco"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}

TEST(TestRuleDataDispatcher, InterfaceInvalidUser)
{
    auto rule = readFile("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "paco"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    {
        ddwaf_object root, ips, user, data, data_point, tmp;

        ddwaf_object_map(&data_point);
        ddwaf_object_map_add(&data_point, "value", ddwaf_object_string(&tmp, "192.168.1.1"));
        ddwaf_object_map_add(&data_point, "expiration", ddwaf_object_string(&tmp, "0"));

        ddwaf_object_array(&data);
        ddwaf_object_array_add(&data, &data_point);

        ddwaf_object_map(&ips);
        ddwaf_object_map_add(&ips, "type", ddwaf_object_string(&tmp, "ip_with_expiration"));
        ddwaf_object_map_add(&ips, "id", ddwaf_object_string(&tmp, "ip_data"));
        ddwaf_object_map_add(&ips, "data", &data);


        ddwaf_object_map(&data_point);
        ddwaf_object_map_add(&data_point, "value", ddwaf_object_string(&tmp, "paco"));
        ddwaf_object_map_add(&data_point, "expiration", ddwaf_object_string(&tmp, "0"));

        ddwaf_object_array(&data);
        ddwaf_object_array_add(&data, &data_point);

        ddwaf_object_map(&user);
        // Missing type
        ddwaf_object_map_add(&user, "id", ddwaf_object_string(&tmp, "usr_data"));
        ddwaf_object_map_add(&user, "data", &data);

        ddwaf_object_array(&root);
        ddwaf_object_array_add(&root, &ips);
        ddwaf_object_array_add(&root, &user);

        EXPECT_EQ(ddwaf_update_rule_data(handle, &root), DDWAF_OK);
        ddwaf_object_free(&root);
    }

    {
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_MATCH);

        ddwaf_context_destroy(context);
    }

    {
        // The user data update was invalid, so it'll be ignored
        ddwaf_context context = ddwaf_context_init(handle);
        ASSERT_NE(context, nullptr);

        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "usr.id", ddwaf_object_string(&tmp, "paco"));

        EXPECT_EQ(ddwaf_run(context, &root, NULL, LONG_TIME), DDWAF_OK);

        ddwaf_context_destroy(context);
    }

    ddwaf_destroy(handle);
}


TEST(TestRuleDataDispatcher, Basic)
{
    std::vector<ddwaf::manifest::target_type> targets;

    ddwaf::manifest_builder mb;
    targets.push_back(mb.insert("http.client_ip", {}));

    auto manifest = mb.build_manifest();

    condition cond(std::move(targets), {},
        std::make_unique<rule_processor::ip_match>());

    rule_data::dispatcher dispatcher;

    dispatcher.register_condition<rule_processor::ip_match>("id", cond);

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};

        auto match = cond.match(store, manifest, true, deadline);
        EXPECT_FALSE(match.has_value());
    }

    {
        ddwaf_object data, data_point, tmp;

        ddwaf_object_map(&data_point);
        ddwaf_object_map_add(&data_point, "value", ddwaf_object_string(&tmp, "192.168.1.1"));
        ddwaf_object_map_add(&data_point, "expiration", ddwaf_object_string(&tmp, "0"));

        ddwaf_object_array(&data);
        ddwaf_object_array_add(&data, &data_point);

        ddwaf::parameter param = data;
        dispatcher.dispatch("id", "ip_with_expiration", param);

        ddwaf_object_free(&data);
    }

    {
        ddwaf_object root, tmp;
        ddwaf_object_map(&root);
        ddwaf_object_map_add(&root, "http.client_ip", ddwaf_object_string(&tmp, "192.168.1.1"));

        ddwaf::object_store store(manifest);
        store.insert(root);

        ddwaf::timer deadline{2s};

        auto match = cond.match(store, manifest, true, deadline);
        EXPECT_TRUE(match.has_value());

        EXPECT_STREQ(match->resolved.c_str(), "192.168.1.1");
        EXPECT_STREQ(match->matched.c_str(), "192.168.1.1");
        EXPECT_STREQ(match->operator_name.data(), "ip_match");
        EXPECT_STREQ(match->source.data(), "http.client_ip");
        EXPECT_TRUE(match->key_path.empty());
    }
}

TEST(TestRuleDataDispatcher, MultipleProcessorTypes)
{
    ddwaf::manifest_builder mb;
    auto client_ip_target = mb.insert("http.client_ip", {});
    auto usr_id_target = mb.insert("usr.id", {});
    auto manifest = mb.build_manifest();

    condition cond1({client_ip_target}, {},
        std::make_unique<rule_processor::ip_match>());

    condition cond2({usr_id_target}, {},
        std::make_unique<rule_processor::exact_match>());

    rule_data::dispatcher dispatcher;

    dispatcher.register_condition<rule_processor::ip_match>("id", cond1);
    dispatcher.register_condition<rule_processor::exact_match>("id", cond2);
}

TEST(TestRuleDataDispatcher, ConflictingProcessorTypes)
{
    ddwaf::manifest_builder mb;
    auto target = mb.insert("http.client_ip", {});
    auto manifest = mb.build_manifest();

    condition cond1({target}, {},
        std::make_unique<rule_processor::ip_match>());

    condition cond2({target}, {},
        std::make_unique<rule_processor::mock_processor>());

    rule_data::dispatcher dispatcher;

    dispatcher.register_condition<rule_processor::ip_match>("id", cond1);
    EXPECT_THROW(
        dispatcher.register_condition<rule_processor::mock_processor>("id", cond2),
        std::bad_cast);
}
