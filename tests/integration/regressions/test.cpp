// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace std::literals;

namespace {
constexpr std::string_view base_dir = "integration/regressions/";

TEST(TestRegressionsIntegration, DuplicateFlowMatches)
{
    auto *alloc = ddwaf_get_default_allocator();
    auto rule = read_file<ddwaf_object>("regressions2.yaml", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_destroy(&rule, alloc);

    ddwaf_context context = ddwaf_context_init(handle, alloc);
    ASSERT_NE(context, nullptr);

    ddwaf_object parameter;
    ddwaf_object_set_map(&parameter, 2, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&parameter, STRL("param1"), alloc), STRL("Sqreen"), alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(&parameter, STRL("param2"), alloc), STRL("Duplicate"), alloc);

    ddwaf_object ret;
    EXPECT_EQ(ddwaf_context_eval(context, &parameter, alloc, &ret, LONG_TIME), DDWAF_MATCH);

    const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
    EXPECT_FALSE(ddwaf_object_get_bool(timeout));
    EXPECT_EVENTS(ret, {.id = "2",
                           .name = "rule2",
                           .tags = {{"type", "flow1"}, {"category", "category2"}},
                           .matches = {{.op = "match_regex",
                                           .op_value = "Sqreen",
                                           .highlight = "Sqreen"sv,
                                           .args = {{
                                               .value = "Sqreen"sv,
                                               .address = "param1",
                                           }}},
                               {.op = "match_regex",
                                   .op_value = "Duplicate",
                                   .highlight = "Duplicate"sv,
                                   .args = {{
                                       .value = "Duplicate"sv,
                                       .address = "param2",
                                   }}}}});

    ddwaf_object_destroy(&ret, alloc);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

// Data sets with no entries used to crash the build, and the matchers of data
// sets which don't change between builds are shared by the handles.
TEST(TestRegressionsIntegration, EmptyAndUnchangedRuleData)
{
    auto *alloc = ddwaf_get_default_allocator();
    ddwaf_builder builder = ddwaf_builder_init();

    auto add_config = [&](std::string_view path, const std::string &yaml) {
        auto config = yaml_to_object<ddwaf_object>(yaml);
        ASSERT_NE(config.type, DDWAF_OBJ_INVALID);
        EXPECT_TRUE(ddwaf_builder_add_or_update_config(
            builder, path.data(), path.size(), &config, nullptr));
        ddwaf_object_destroy(&config, alloc);
    };

    auto count_events = [&](ddwaf_handle handle) -> std::size_t {
        ddwaf_context context = ddwaf_context_init(handle, alloc);
        EXPECT_NE(context, nullptr);

        ddwaf_object root;
        ddwaf_object_set_map(&root, 2, alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("http.client_ip"), alloc), STRL("1.2.3.4"), alloc);
        ddwaf_object_set_string(
            ddwaf_object_insert_key(&root, STRL("usr.id"), alloc), STRL("admin"), alloc);

        ddwaf_object out;
        ddwaf_context_eval(context, &root, alloc, &out, LONG_TIME);
        const auto *events = ddwaf_object_find(&out, STRL("events"));
        const std::size_t count = events != nullptr ? ddwaf_object_get_size(events) : 0;
        ddwaf_object_destroy(&out, alloc);
        ddwaf_context_destroy(context);
        return count;
    };

    add_config("rules", R"({version: '2.1', rules: [
        {id: 1, name: rule1, tags: {type: type1, category: category}, conditions: [
            {operator: ip_match, parameters: {inputs: [{address: http.client_ip}], data: blocked_ips}}]},
        {id: 2, name: rule2, tags: {type: type2, category: category}, conditions: [
            {operator: exact_match, parameters: {inputs: [{address: usr.id}], data: blocked_users}}]}
    ]})");
    add_config("data1", R"({rules_data: [
        {id: blocked_ips, type: ip_with_expiration, data: []},
        {id: blocked_users, type: data_with_expiration, data: [{value: admin}]}
    ]})");

    ddwaf_handle handle1 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle1, nullptr);
    EXPECT_EQ(count_events(handle1), 1);

    // blocked_users doesn't change, so its matcher is shared with handle1
    add_config("data2", R"({rules_data: [
        {id: blocked_ips, type: ip_with_expiration, data: [{value: 1.2.3.4}]}
    ]})");
    ddwaf_handle handle2 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle2, nullptr);
    ddwaf_destroy(handle1);
    EXPECT_EQ(count_events(handle2), 2);

    add_config("data2", R"({rules_data: [
        {id: blocked_ips, type: ip_with_expiration, data: [{value: 1.2.3.5}]}
    ]})");
    ddwaf_handle handle3 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle3, nullptr);
    EXPECT_EQ(count_events(handle3), 1);
    EXPECT_EQ(count_events(handle2), 2);
    ddwaf_destroy(handle2);
    EXPECT_EQ(count_events(handle3), 1);

    add_config("data3", R"({rules_data: [
        {id: blocked_users, type: data_with_expiration, data: []}
    ]})");
    ddwaf_handle handle4 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle4, nullptr);
    EXPECT_EQ(count_events(handle4), 1);

    ddwaf_builder_remove_config(builder, LSTRARG("data1"));
    ddwaf_handle handle5 = ddwaf_builder_build_instance(builder);
    ASSERT_NE(handle5, nullptr);
    EXPECT_EQ(count_events(handle5), 0);
    EXPECT_EQ(count_events(handle4), 1);

    ddwaf_destroy(handle3);
    ddwaf_destroy(handle4);
    ddwaf_destroy(handle5);
    ddwaf_builder_destroy(builder);
}

} // namespace
