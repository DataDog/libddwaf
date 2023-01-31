// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "ddwaf.h"
#include "test.h"

using namespace ddwaf;

TEST(TestInterface, RootAddresses)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *addresses = ddwaf_required_addresses(handle, &size);
    EXPECT_EQ(size, 2);

    std::set<std::string_view> available_addresses{"value1", "value2"};
    while ((size--) != 0U) {
        EXPECT_NE(available_addresses.find(addresses[size]), available_addresses.end());
    }

    ddwaf_destroy(handle);
}

TEST(TestInterface, RuleDatIDs)
{
    auto rule = readFile("rule_data.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *ids = ddwaf_required_rule_data_ids(handle, &size);
    EXPECT_EQ(size, 2);

    std::set<std::string_view> available_ids{"usr_data", "ip_data"};
    while ((size--) != 0U) { EXPECT_NE(available_ids.find(ids[size]), available_ids.end()); }

    ddwaf_destroy(handle);
}

TEST(TestInterface, EmptyRuleDatIDs)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    uint32_t size;
    const char *const *ids = ddwaf_required_rule_data_ids(handle, &size);
    EXPECT_EQ(ids, nullptr);
    EXPECT_EQ(size, 0);

    ddwaf_destroy(handle);
}

TEST(TestInterface, HandleLifetime)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object param_key = DDWAF_OBJECT_ARRAY, param_val = DDWAF_OBJECT_ARRAY;

    ddwaf_object_array_add(&param_key, ddwaf_object_unsigned(&tmp, 4242));
    ddwaf_object_array_add(&param_key, ddwaf_object_string(&tmp, "randomString"));

    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object_map_add(&parameter, "value1", &param_key);
    ddwaf_object_map_add(&parameter, "value2", &param_val);

    EXPECT_EQ(ddwaf_run(context, &parameter, NULL, LONG_TIME), DDWAF_MATCH);

    ddwaf_object_free(&parameter);
    ddwaf_context_destroy(context);
}

TEST(TestInterface, HandleLifetimeMultipleContexts)
{
    auto rule = readFile("interface.yaml");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_config config{{0, 0, 0}, {nullptr, nullptr}, nullptr};

    ddwaf_handle handle = ddwaf_init(&rule, &config, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context1 = ddwaf_context_init(handle);
    ASSERT_NE(context1, nullptr);

    ddwaf_context context2 = ddwaf_context_init(handle);
    ASSERT_NE(context2, nullptr);

    // Destroying the handle should not invalidate it
    ddwaf_destroy(handle);

    ddwaf_object parameter = DDWAF_OBJECT_MAP, tmp;
    ddwaf_object param_key = DDWAF_OBJECT_ARRAY, param_val = DDWAF_OBJECT_ARRAY;

    ddwaf_object_array_add(&param_key, ddwaf_object_unsigned(&tmp, 4242));
    ddwaf_object_array_add(&param_key, ddwaf_object_string(&tmp, "randomString"));

    ddwaf_object_array_add(&param_val, ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object_map_add(&parameter, "value1", &param_key);
    ddwaf_object_map_add(&parameter, "value2", &param_val);

    EXPECT_EQ(ddwaf_run(context1, &parameter, NULL, LONG_TIME), DDWAF_MATCH);
    ddwaf_context_destroy(context1);

    EXPECT_EQ(ddwaf_run(context2, &parameter, NULL, LONG_TIME), DDWAF_MATCH);
    ddwaf_context_destroy(context2);

    ddwaf_object_free(&parameter);
}
