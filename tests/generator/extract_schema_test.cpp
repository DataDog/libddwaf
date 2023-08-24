// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "../test_utils.hpp"
#include "generator/extract_schema.hpp"

using namespace ddwaf;

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define EXPECT_SCHEMA_EQ(obtained, expected)                                                       \
  {                                                                                                \
    auto obtained_doc = test::object_to_rapidjson(obtained);                                       \
    EXPECT_TRUE(ValidateSchemaSchema(obtained_doc));                                               \
    rapidjson::Document expected_doc;                                                              \
    expected_doc.Parse(expected);                                                                  \
    EXPECT_FALSE(expected_doc.HasParseError());                                                    \
    EXPECT_TRUE(json_equals(obtained_doc, expected_doc)) << test::object_to_json(obtained);        \
  }
// NOLINTEND(cppcoreguidelines-macro-usage)

namespace {

TEST(TestExtractSchema, UnknownScalarSchema)
{
    ddwaf_object input;
    ddwaf_object_invalid(&input);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([0])");

    ddwaf_object_free(&output);
}

TEST(TestExtractSchema, NullScalarSchema)
{
    ddwaf_object input;
    ddwaf_object_null(&input);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([1])");

    ddwaf_object_free(&output);
}

TEST(TestExtractSchema, BoolScalarSchema)
{
    ddwaf_object input;
    ddwaf_object_bool(&input, true);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([2])");

    ddwaf_object_free(&output);
}

TEST(TestExtractSchema, IntScalarSchema)
{
    ddwaf_object input;
    {
        ddwaf_object_unsigned(&input, 5);

        generator::extract_schema gen;

        auto output = gen.generate(&input);
        EXPECT_SCHEMA_EQ(output, R"([4])");

        ddwaf_object_free(&output);
    }
    {
        ddwaf_object_signed(&input, -5);

        generator::extract_schema gen;

        auto output = gen.generate(&input);
        EXPECT_SCHEMA_EQ(output, R"([4])");

        ddwaf_object_free(&output);
    }
}

TEST(TestExtractSchema, StringScalarSchema)
{
    ddwaf_object input;
    ddwaf_object_string(&input, "string");

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([8])");

    ddwaf_object_free(&output);
    ddwaf_object_free(&input);
}

TEST(TestExtractSchema, FloatScalarSchema)
{
    ddwaf_object input;
    ddwaf_object_float(&input, 1.5);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([16])");

    ddwaf_object_free(&output);
}

TEST(TestExtractSchema, EmptyArraySchema)
{
    ddwaf_object input;
    ddwaf_object_array(&input);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([[],{"len":0}])");

    ddwaf_object_free(&output);
}

TEST(TestExtractSchema, ArraySchema)
{
    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_array(&input);
    ddwaf_object_array_add(&input, ddwaf_object_unsigned(&tmp, 22));
    ddwaf_object_array_add(&input, ddwaf_object_string(&tmp, "string"));
    ddwaf_object_array_add(&input, ddwaf_object_invalid(&tmp));
    ddwaf_object_array_add(&input, ddwaf_object_null(&tmp));

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([[[1],[0],[8],[4]],{"len":4}])");

    ddwaf_object_free(&output);
    ddwaf_object_free(&input);
}

TEST(TestExtractSchema, ArrayWithDuplicateScalarSchema)
{
    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_array(&input);
    ddwaf_object_array_add(&input, ddwaf_object_string(&tmp, "string"));
    ddwaf_object_array_add(&input, ddwaf_object_string(&tmp, "string"));
    ddwaf_object_array_add(&input, ddwaf_object_string(&tmp, "string"));
    ddwaf_object_array_add(&input, ddwaf_object_string(&tmp, "string"));

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([[[8]],{"len":4}])");

    ddwaf_object_free(&output);
    ddwaf_object_free(&input);
}

TEST(TestExtractSchema, ArrayWithDuplicateMapsSchema)
{
    ddwaf_object tmp;

    ddwaf_object input;
    ddwaf_object_array(&input);

    ddwaf_object child;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "unsigned", ddwaf_object_unsigned(&tmp, 5));
    ddwaf_object_map_add(&child, "string", ddwaf_object_string(&tmp, "str"));
    ddwaf_object_array_add(&input, &child);

    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "signed", ddwaf_object_signed(&tmp, -5));
    ddwaf_object_array_add(&input, &child);

    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "unsigned", ddwaf_object_unsigned(&tmp, 5));
    ddwaf_object_array_add(&input, &child);

    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "unsigned", ddwaf_object_unsigned(&tmp, 109));
    ddwaf_object_map_add(&child, "string", ddwaf_object_string(&tmp, "wahtever"));
    ddwaf_object_array_add(&input, &child);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output,
        R"([[[{"unsigned":[4]}],[{"signed":[4]}],[{"string":[8],"unsigned":[4]}]],{"len":4}])");

    ddwaf_object_free(&output);
    ddwaf_object_free(&input);
}

TEST(TestExtractSchema, ArrayWithDuplicateArraysSchema)
{
    ddwaf_object tmp;

    ddwaf_object input;
    ddwaf_object_array(&input);

    ddwaf_object child;
    ddwaf_object_array(&child);
    ddwaf_object_array_add(&child, ddwaf_object_unsigned(&tmp, 5));
    ddwaf_object_array_add(&child, ddwaf_object_string(&tmp, "str"));
    ddwaf_object_array_add(&input, &child);

    ddwaf_object_array(&child);
    ddwaf_object_array_add(&child, ddwaf_object_signed(&tmp, -5));
    ddwaf_object_array_add(&input, &child);

    ddwaf_object_array(&child);
    ddwaf_object_array_add(&child, ddwaf_object_unsigned(&tmp, 5));
    ddwaf_object_array_add(&input, &child);

    ddwaf_object_array(&child);
    ddwaf_object_array_add(&child, ddwaf_object_unsigned(&tmp, 109));
    ddwaf_object_array_add(&child, ddwaf_object_string(&tmp, "wahtever"));
    ddwaf_object_array_add(&input, &child);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([[[[[4]],{"len":1}],[[[8],[4]],{"len":2}]],{"len":4}])");

    ddwaf_object_free(&output);
    ddwaf_object_free(&input);
}

TEST(TestExtractSchema, ArrayWithDuplicateContainersSchema)
{
    ddwaf_object tmp;

    ddwaf_object input;
    ddwaf_object_array(&input);

    ddwaf_object child;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "unsigned", ddwaf_object_unsigned(&tmp, 5));
    ddwaf_object_map_add(&child, "string", ddwaf_object_string(&tmp, "str"));
    ddwaf_object_array_add(&input, &child);

    ddwaf_object_array(&child);
    ddwaf_object_array_add(&child, ddwaf_object_signed(&tmp, -5));
    ddwaf_object_array_add(&input, &child);

    ddwaf_object_array(&child);
    ddwaf_object_array_add(&child, ddwaf_object_unsigned(&tmp, 5));
    ddwaf_object_array_add(&input, &child);

    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "string", ddwaf_object_string(&tmp, "wahtever"));
    ddwaf_object_map_add(&child, "unsigned", ddwaf_object_unsigned(&tmp, 109));
    ddwaf_object_array_add(&input, &child);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([[[[[4]],{"len":1}],[{"string":[8],"unsigned":[4]}]],{"len":4}])");

    ddwaf_object_free(&output);
    ddwaf_object_free(&input);
}

TEST(TestExtractSchema, EmptyMapSchema)
{
    ddwaf_object input;
    ddwaf_object_map(&input);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([{}])");

    ddwaf_object_free(&output);
}

TEST(TestExtractSchema, MapSchema)
{
    ddwaf_object tmp;
    ddwaf_object input;
    ddwaf_object_map(&input);
    ddwaf_object_map_add(&input, "unsigned", ddwaf_object_unsigned(&tmp, 22));
    ddwaf_object_map_add(&input, "string", ddwaf_object_string(&tmp, "string"));
    ddwaf_object_map_add(&input, "invalid", ddwaf_object_invalid(&tmp));
    ddwaf_object_map_add(&input, "null", ddwaf_object_null(&tmp));

    ddwaf_object child;
    ddwaf_object_map(&child);
    ddwaf_object_map_add(&child, "unsigned", ddwaf_object_unsigned(&tmp, 5));
    ddwaf_object_map_add(&child, "string", ddwaf_object_string(&tmp, "str"));
    ddwaf_object_map_add(&input, "map", &child);

    ddwaf_object_array(&child);
    ddwaf_object_array_add(&child, ddwaf_object_signed(&tmp, -5));
    ddwaf_object_map_add(&input, "array", &child);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output,
        R"([{"array":[[[4]],{"len":1}],"invalid":[0],"map":[{"unsigned":[4],"string":[8]}],"null":[1],"string":[8],"unsigned":[4]}])");
    ddwaf_object_free(&output);
    ddwaf_object_free(&input);
}

TEST(TestExtractSchema, DepthLimit)
{
    ddwaf_object input;
    ddwaf_object_array(&input);

    ddwaf_object *parent = &input;
    for (unsigned i = 0; i < generator::extract_schema::max_container_depth + 10; ++i) {
        ddwaf_object child;
        ddwaf_object_array(&child);
        ddwaf_object_array_add(parent, &child);
        parent = &parent->array[0];
    }

    generator::extract_schema gen;
    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output,
        R"([[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}])");

    ddwaf_object_free(&output);
    ddwaf_object_free(&input);
}

TEST(TestExtractSchema, ArrayNodesLimit)
{
    ddwaf_object input;
    ddwaf_object_array(&input);
    for (unsigned i = 0; i < generator::extract_schema::max_array_nodes + 10; ++i) {
        ddwaf_object child;
        ddwaf_object_array(&child);
        ddwaf_object_array_add(&input, &child);
    }

    generator::extract_schema gen;
    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([[[[],{"len":0}]],{"len":20,"truncated":true}])");

    ddwaf_object_free(&output);
    ddwaf_object_free(&input);
}

TEST(TestExtractSchema, RecordNodesLimit)
{
    ddwaf_object input;
    ddwaf_object_map(&input);
    for (unsigned i = 0; i < generator::extract_schema::max_record_nodes + 10; ++i) {
        ddwaf_object child;
        ddwaf_object_array(&child);
        ddwaf_object_map_add(&input, "child", &child);
    }

    generator::extract_schema gen;
    auto output = gen.generate(&input);
    EXPECT_SCHEMA_EQ(output, R"([{"child":[[],{"len":0}]},{"truncated":true}])");

    ddwaf_object_free(&output);
    ddwaf_object_free(&input);
}

} // namespace
