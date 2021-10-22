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
            throw std::invalid_argument("Failed to parse schema");
        }

        schema    = std::make_unique<SchemaDocument>(sd);
        validator = std::make_unique<SchemaValidator>(*schema);
    }

    void SetUp()
    {
        validator->Reset();
    }

    bool Validate(const std::string& json)
    {
        Document d;
        if (d.Parse(json).HasParseError())
        {
            return false;
        }

        return d.Accept(*validator);
    }

protected:
    Document sd;
    std::unique_ptr<SchemaDocument> schema;
    std::unique_ptr<SchemaValidator> validator;
};

TEST_F(TestSchemaFixture, BasicTest)
{
    //Initialize a PowerWAF rule
    auto rule = readRule(R"({version: '2.1', rules: [{id: 1, name: rule1, tags: {type: flow1, category: category1}, conditions: [{operator: match_regex, parameters: {inputs: [{address: arg1}], regex: .*}}, {operator: match_regex, parameters: {inputs: [{address: arg2}], regex: .*}}]}]})");
    ASSERT_TRUE(rule.type != DDWAF_OBJ_INVALID);

    ddwaf_handle handle = ddwaf_init(&rule, nullptr);
    ASSERT_NE(handle, nullptr);
    ddwaf_object_free(&rule);

    ddwaf_context context = ddwaf_context_init(handle, ddwaf_object_free);
    ASSERT_NE(context, nullptr);

    ddwaf_object param, tmp;
    ddwaf_object_map(&param);

    ddwaf_object_map_add(&param, "arg1", ddwaf_object_string(&tmp, "string 1"));
    ddwaf_object_map_add(&param, "arg2", ddwaf_object_string(&tmp, "string 2"));

    ddwaf_result ret;
    ddwaf_run(context, &param, &ret, LONG_TIME);
    EXPECT_TRUE(Validate(ret.data));
    ddwaf_result_free(&ret);

    ddwaf_context_destroy(context);
    ddwaf_destroy(handle);
}
