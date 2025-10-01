// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "ddwaf.h"

using namespace rapidjson;

namespace {

constexpr std::string_view base_dir = "integration/events/schema/";

class TestSchemaIntegration : public ::testing::Test {
public:
    TestSchemaIntegration()
    {
        auto rule = read_file<ddwaf_object>("schema.yaml", base_dir);
        if (ddwaf_object_is_invalid(&rule)) {
            throw std::runtime_error("failed to load schema.yaml");
        }

        handle = ddwaf_init(&rule, nullptr);
        if (handle == nullptr) {
            throw std::runtime_error("failed to obtain waf handle");
        }

        ddwaf_object_destroy(&rule, ddwaf_get_default_allocator());
    }

    ~TestSchemaIntegration() { ddwaf_destroy(handle); }

    void SetUp()
    {
        context = ddwaf_context_init(handle, ddwaf_get_default_allocator());
        ASSERT_NE(context, nullptr);
    }

    void TearDown()
    {
        ddwaf_context_destroy(context);
        context = nullptr;
    }

    void Validate(ddwaf_object ret, DDWAF_RET_CODE code)
    {
        Document d;
        EXPECT_EQ(code, DDWAF_MATCH);

        const auto *events = ddwaf_object_find(&ret, STRL("events"));
        ASSERT_EQ(ddwaf_object_get_type(events), DDWAF_OBJ_ARRAY);
        ASSERT_GT(ddwaf_object_get_size(events), 0);

        const auto *timeout = ddwaf_object_find(&ret, STRL("timeout"));
        EXPECT_FALSE(ddwaf_object_get_bool(timeout));

        auto data = ddwaf::test::object_to_json(*events);
        if (!HasFailure()) {
            EXPECT_TRUE(ValidateEventSchema(data));
        }
    }

protected:
    Document sd;
    std::unique_ptr<SchemaDocument> schema;
    std::unique_ptr<SchemaValidator> validator;

    ddwaf_handle handle{nullptr};

    ddwaf_context context{nullptr};
};

TEST_F(TestSchemaIntegration, SimpleResult)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object param;
    ddwaf_object_set_map(&param, 1, alloc);

    ddwaf_object_set_string(
        ddwaf_object_insert_key(&param, STRL("arg1"), alloc), STRL("rule1"), alloc);

    ddwaf_object ret;
    auto code = ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_object_destroy(&ret, alloc);
}

TEST_F(TestSchemaIntegration, SimpleResultWithKeyPath)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object param;
    ddwaf_object_set_map(&param, 1, alloc);
    auto *arg2 = ddwaf_object_insert_key(&param, STRL("arg2"), alloc);
    ddwaf_object_set_map(arg2, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(arg2, STRL("key1"), alloc), STRL("rule2"), alloc);

    ddwaf_object ret;
    auto code = ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_object_destroy(&ret, alloc);
}

TEST_F(TestSchemaIntegration, SimpleResultWithMultiKeyPath)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object param;
    ddwaf_object_set_map(&param, 1, alloc);

    auto *arg2 = ddwaf_object_insert_key(&param, STRL("arg2"), alloc);
    ddwaf_object_set_map(arg2, 1, alloc);

    auto *array = ddwaf_object_insert_key(arg2, STRL("key1"), alloc);
    ddwaf_object_set_array(array, 1, alloc);
    ddwaf_object_set_string(ddwaf_object_insert(array, alloc), STRL("rule2"), alloc);

    ddwaf_object ret;
    auto code = ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_object_destroy(&ret, alloc);
}

TEST_F(TestSchemaIntegration, ResultWithMultiCondition)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object param;
    ddwaf_object_set_map(&param, 2, alloc);

    auto *arg4 = ddwaf_object_insert_key(&param, STRL("arg4"), alloc);
    ddwaf_object_set_map(arg4, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(arg4, STRL("key1"), alloc), STRL("rule3"), alloc);

    ddwaf_object_set_string(
        ddwaf_object_insert_key(&param, STRL("arg3"), alloc), STRL("rule3_value"), alloc);

    ddwaf_object ret;
    auto code = ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_object_destroy(&ret, alloc);
}

TEST_F(TestSchemaIntegration, MultiResultWithMultiCondition)
{
    auto *alloc = ddwaf_get_default_allocator();

    ddwaf_object param;
    ddwaf_object_set_map(&param, 4, alloc);

    ddwaf_object_set_string(
        ddwaf_object_insert_key(&param, STRL("arg1"), alloc), STRL("rule1"), alloc);

    auto *arg2 = ddwaf_object_insert_key(&param, STRL("arg2"), alloc);
    ddwaf_object_set_map(arg2, 1, alloc);

    auto *array = ddwaf_object_insert_key(arg2, STRL("key1"), alloc);
    ddwaf_object_set_array(array, 1, alloc);
    ddwaf_object_set_string(ddwaf_object_insert(array, alloc), STRL("rule2"), alloc);

    ddwaf_object_set_string(
        ddwaf_object_insert_key(&param, STRL("arg3"), alloc), STRL("rule3_value"), alloc);

    auto *arg4 = ddwaf_object_insert_key(&param, STRL("arg4"), alloc);
    ddwaf_object_set_map(arg4, 1, alloc);
    ddwaf_object_set_string(
        ddwaf_object_insert_key(arg4, STRL("key1"), alloc), STRL("rule3"), alloc);

    ddwaf_object ret;
    auto code = ddwaf_context_eval(context, &param, alloc, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_object_destroy(&ret, alloc);
}

} // namespace
