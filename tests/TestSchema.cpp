#include "rapidjson/prettywriter.h"
#include "rapidjson/schema.h"
#include "test.h"
#include <fstream>
#include <memory>

using namespace rapidjson;

class TestSchemaFixture : public ::testing::Test
{
public:
    TestSchemaFixture()
    {
        std::ifstream rule_file("../schema/appsec-event-1.0.0.json", std::ios::in);
        if (!rule_file)
        {
            throw std::system_error(errno, std::generic_category());
        }

        std::string buffer;
        rule_file.seekg(0, std::ios::end);
        buffer.resize(rule_file.tellg());
        rule_file.seekg(0, std::ios::beg);

        rule_file.read(&buffer[0], buffer.size());
        rule_file.close();

        if (sd.Parse(buffer).HasParseError())
        {
            throw std::runtime_error("failed to parse schema");
        }

        schema    = std::make_unique<SchemaDocument>(sd);
        validator = std::make_unique<SchemaValidator>(*schema);

        auto rule = readFile("schema.yaml");
        if (rule.type == DDWAF_OBJ_INVALID)
        {
            throw std::runtime_error("failed to load schema.yaml");
        }

        handle = ddwaf_init(&rule, nullptr, nullptr);
        if (handle == nullptr)
        {
            throw std::runtime_error("failed to obtain waf handle");
        }

        ddwaf_object_free(&rule);
    }

    ~TestSchemaFixture()
    {
        ddwaf_destroy(handle);
    }

    void SetUp()
    {
        validator->Reset();

        context = ddwaf_context_init(handle, ddwaf_object_free);
        ASSERT_NE(context, nullptr);
    }

    void TearDown()
    {
        ddwaf_context_destroy(context);
        context = nullptr;
    }

    std::string Error()
    {
        StringBuffer sb;
        PrettyWriter<StringBuffer> w(sb);
        validator->GetError().Accept(w);
        return sb.GetString();
    }

    void Validate(ddwaf_result ret, DDWAF_RET_CODE code)
    {
        Document d;
        EXPECT_EQ(code, DDWAF_MONITOR);
        EXPECT_NE(ret.data, nullptr);
        EXPECT_FALSE(ret.timeout);
        if (!HasFailure())
        {
            EXPECT_FALSE(d.Parse(ret.data).HasParseError());
            EXPECT_TRUE(d.Accept(*validator)) << Error();
        }
    }

protected:
    Document sd;
    std::unique_ptr<SchemaDocument> schema;
    std::unique_ptr<SchemaValidator> validator;

    ddwaf_handle handle { nullptr };

    ddwaf_context context { nullptr };
};

TEST_F(TestSchemaFixture, SimpleResult)
{
    ddwaf_object param, tmp;
    ddwaf_object_map(&param);

    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "rule1"));

    ddwaf_result ret;
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_result_free(&ret);
}

TEST_F(TestSchemaFixture, SimpleResultWithKeyPath)
{
    ddwaf_object param, arg2, tmp;
    ddwaf_object_map(&param);
    ddwaf_object_map(&arg2);
    ddwaf_object_map_add(&arg2, "key1", ddwaf_object_string(&tmp, "rule2"));
    ddwaf_object_map_add(&param, "arg2", &arg2);

    ddwaf_result ret;
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_result_free(&ret);
}

TEST_F(TestSchemaFixture, SimpleResultWithMultiKeyPath)
{
    ddwaf_object param, arg2, array, tmp;
    ddwaf_object_map(&param);

    ddwaf_object_array(&array);
    ddwaf_object_array_add(&array, ddwaf_object_string(&tmp, "rule2"));
    ddwaf_object_map(&arg2);
    ddwaf_object_map_add(&arg2, "key1", &array);
    ddwaf_object_map_add(&param, "arg2", &arg2);

    ddwaf_result ret;
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_result_free(&ret);
}

TEST_F(TestSchemaFixture, ResultWithMultiCondition)
{
    ddwaf_object param, arg4, tmp;
    ddwaf_object_map(&param);

    ddwaf_object_map_add(&param, "arg3", ddwaf_object_string(&tmp, "rule3_value"));

    ddwaf_object_map(&arg4);
    ddwaf_object_map_add(&arg4, "key1", ddwaf_object_string(&tmp, "rule3"));
    ddwaf_object_map_add(&param, "arg4", &arg4);

    ddwaf_result ret;
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_result_free(&ret);
}

TEST_F(TestSchemaFixture, MultiResultWithMultiCondition)
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

    ddwaf_result ret;
    auto code = ddwaf_run(context, &param, nullptr, &ret, LONG_TIME);
    Validate(ret, code);
    ddwaf_result_free(&ret);
}
