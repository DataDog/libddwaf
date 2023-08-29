// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "../../test_utils.hpp"

using namespace ddwaf;

namespace {
constexpr std::string_view base_dir = "integration/processors/";
} // namespace

TEST(TestProcessors, Postprocessor)
{
    auto rule = read_json_file("postprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object value;

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object_string(&value, "value");
    ddwaf_object_map_add(&map, "server.request.body", &value);

    ddwaf_object_bool(&value, true);
    ddwaf_object_map_add(&settings, "extract-schema", &value);
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_OK);
    EXPECT_FALSE(out.timeout);

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

    auto schema = test::object_to_json(out.derivatives);
    EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestProcessors, Preprocessor)
{
    auto rule = read_json_file("preprocessor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object value;

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object_string(&value, "value");
    ddwaf_object_map_add(&map, "server.request.body", &value);

    ddwaf_object_bool(&value, true);
    ddwaf_object_map_add(&settings, "extract-schema", &value);
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);

    EXPECT_EVENTS(out, {.id = "rule1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "equals",
                               .op_value = "",
                               .address = "server.request.body.schema",
                               .path = {"0"},
                               .value = "8",
                               .highlight = ""}}});

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 0);

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}

TEST(TestProcessors, Processor)
{
    auto rule = read_json_file("processor.json", base_dir);
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);
    ddwaf_handle handle = ddwaf_init(&rule, nullptr, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle);
    ASSERT_NE(context, nullptr);

    ddwaf_object value;

    ddwaf_object map = DDWAF_OBJECT_MAP;
    ddwaf_object settings = DDWAF_OBJECT_MAP;

    ddwaf_object_string(&value, "value");
    ddwaf_object_map_add(&map, "server.request.body", &value);

    ddwaf_object_bool(&value, true);
    ddwaf_object_map_add(&settings, "extract-schema", &value);
    ddwaf_object_map_add(&map, "waf.context.processor", &settings);

    ddwaf_result out;
    ASSERT_EQ(ddwaf_run(context, &map, &out, 2000), DDWAF_MATCH);
    EXPECT_FALSE(out.timeout);

    EXPECT_EVENTS(out, {.id = "rule1",
                           .name = "rule1",
                           .tags = {{"type", "flow1"}, {"category", "category1"}},
                           .matches = {{.op = "equals",
                               .op_value = "",
                               .address = "server.request.body.schema",
                               .path = {"0"},
                               .value = "8",
                               .highlight = ""}}});

    EXPECT_EQ(ddwaf_object_size(&out.derivatives), 1);

    auto schema = test::object_to_json(out.derivatives);
    EXPECT_STR(schema, R"({"server.request.body.schema":[8]})");

    ddwaf_result_free(&out);
    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
