// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include "common/gtest_utils.hpp"

using namespace rapidjson;

namespace {

constexpr std::string_view base_dir = "integration/events/schema/";

class TestSchemaIntegration : public ::testing::Test {
public:
    TestSchemaIntegration()
    {
        auto rule = read_file("schema.yaml", base_dir);
        if (rule.type == DDWAF_OBJ_INVALID) {
            throw std::runtime_error("failed to load schema.yaml");
        }

        handle = ddwaf_init(&rule, nullptr, nullptr);
        if (handle == nullptr) {
            throw std::runtime_error("failed to obtain waf handle");
        }

        ddwaf_object_free(&rule);
    }

    ~TestSchemaIntegration() { ddwaf_destroy(handle); }

    void SetUp()
    {
        context = ddwaf_context_init(handle);
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
        ASSERT_EQ(ddwaf_object_type(events), DDWAF_OBJ_ARRAY);
        ASSERT_GT(ddwaf_object_size(events), 0);

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
    ddwaf_object param, tmp;
    ddwaf_object_map(&param);

    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object ret;
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_object_free(&ret);
}

TEST_F(TestSchemaIntegration, SimpleResultWithKeyPath)
{
    ddwaf_object param, arg2, tmp;
    ddwaf_object_map(&param);
    ddwaf_object_map(&arg2);
    ddwaf_object_map_add(&arg2, "key1", ddwaf_object_string(&tmp, "rule2"));
    ddwaf_object_map_add(&param, "arg2", &arg2);

    ddwaf_object ret;
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_object_free(&ret);
}

TEST_F(TestSchemaIntegration, SimpleResultWithMultiKeyPath)
{
    ddwaf_object param, arg2, array, tmp;
    ddwaf_object_map(&param);

    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "rule2"));
    ddwaf_object_map(&arg2);
    ddwaf_object_map_add(&arg2, "key1", &array);
    ddwaf_object_map_add(&param, "arg2", &arg2);

    ddwaf_object ret;
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_object_free(&ret);
}

TEST_F(TestSchemaIntegration, ResultWithMultiCondition)
{
    ddwaf_object param, arg4, tmp;
    ddwaf_object_map(&param);

    ddwaf_object_map_add(&param, "arg3", ddwaf_object_string(&tmp, "rule3_value"));

    ddwaf_object_map(&arg4);
    ddwaf_object_map_add(&arg4, "key1", ddwaf_object_string(&tmp, "rule3"));
    ddwaf_object_map_add(&param, "arg4", &arg4);

    ddwaf_object ret;
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_object_free(&ret);
}

TEST_F(TestSchemaIntegration, MultiResultWithMultiCondition)
{
    ddwaf_object param, arg2, arg4, array, tmp;
    ddwaf_object_map(&param);

    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "rule1"));

    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "rule2"));
    ddwaf_object_map(&arg2);
    ddwaf_object_map_add(&arg2, "key1", &array);
    ddwaf_object_map_add(&param, "arg2", &arg2);

    ddwaf_object_map_add(&param, "arg3", ddwaf_object_string(&tmp, "rule3_value"));

    ddwaf_object_map(&arg4);
    ddwaf_object_map_add(&arg4, "key1", ddwaf_object_string(&tmp, "rule3"));
    ddwaf_object_map_add(&param, "arg4", &arg4);

    ddwaf_object ret;
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_object_free(&ret);
}

} // namespace
