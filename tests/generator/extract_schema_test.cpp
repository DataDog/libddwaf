// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "../test_utils.hpp"
#include "generator/extract_schema.hpp"

using namespace ddwaf;

namespace {

TEST(TestExtractSchema, UnknownScalarSchema)
{
    ddwaf_object input;
    ddwaf_object_invalid(&input);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);

    EXPECT_STR(schema, R"([0])");
}

TEST(TestExtractSchema, NullScalarSchema)
{
    ddwaf_object input;
    ddwaf_object_null(&input);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);

    EXPECT_STR(schema, R"([1])");
}

TEST(TestExtractSchema, BoolScalarSchema)
{
    ddwaf_object input;
    ddwaf_object_bool(&input, true);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);

    EXPECT_STR(schema, R"([2])");
}

TEST(TestExtractSchema, IntScalarSchema)
{
    ddwaf_object input;
    {
        ddwaf_object_unsigned(&input, 5);

        generator::extract_schema gen;

        auto output = gen.generate(&input);
        auto schema = test::object_to_json(output);
        ddwaf_object_free(&output);

        EXPECT_STR(schema, R"([4])");
    }
    {
        ddwaf_object_signed(&input, -5);

        generator::extract_schema gen;

        auto output = gen.generate(&input);
        auto schema = test::object_to_json(output);
        ddwaf_object_free(&output);

        EXPECT_STR(schema, R"([4])");
    }
}

TEST(TestExtractSchema, StringScalarSchema)
{
    ddwaf_object input;
    ddwaf_object_string(&input, "string");

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);

    EXPECT_STR(schema, R"([8])");

    ddwaf_object_free(&input);
}

TEST(TestExtractSchema, FloatScalarSchema)
{
    ddwaf_object input;
    ddwaf_object_float(&input, 1.5);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);

    EXPECT_STR(schema, R"([16])");
}

TEST(TestExtractSchema, EmptyArraySchema)
{
    ddwaf_object input;
    ddwaf_object_array(&input);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);

    EXPECT_STR(schema, R"([[],{"len":0}])");
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
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);
    ddwaf_object_free(&input);

    EXPECT_STR(schema, R"([[[1],[0],[8],[4]],{"len":4}])");
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
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);
    ddwaf_object_free(&input);

    EXPECT_STR(schema, R"([[[8]],{"len":4}])");
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
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);
    ddwaf_object_free(&input);

    EXPECT_STR(schema,
        R"([[[{"unsigned":[4]}],[{"signed":[4]}],[{"string":[8],"unsigned":[4]}]],{"len":4}])");
}

TEST(TestExtractSchema, EmptyMapSchema)
{
    ddwaf_object input;
    ddwaf_object_map(&input);

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);

    EXPECT_STR(schema, R"([{}])");
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

    generator::extract_schema gen;

    auto output = gen.generate(&input);
    auto schema = test::object_to_json(output);
    ddwaf_object_free(&output);
    ddwaf_object_free(&input);

    EXPECT_STR(schema, R"([{"invalid":[0],"null":[1],"string":[8],"unsigned":[4]}])");
}

} // namespace
