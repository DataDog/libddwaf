// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"
#include "matcher/regex_match.hpp"
#include "memory_resource.hpp"
#include "processor/extract_schema.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

TEST(TestExtractSchema, UnknownScalarSchema)
{
    auto *alloc = memory::get_default_resource();

    owned_object input = owned_object{};

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([0])");
}

TEST(TestExtractSchema, NullScalarSchema)
{
    auto *alloc = memory::get_default_resource();

    auto input = owned_object::make_null();

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([1])");
}

TEST(TestExtractSchema, BoolScalarSchema)
{
    auto *alloc = memory::get_default_resource();

    owned_object input = test::ddwaf_object_da::make_boolean(true);

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([2])");
}

TEST(TestExtractSchema, IntScalarSchema)
{
    auto *alloc = memory::get_default_resource();

    {
        owned_object input = test::ddwaf_object_da::make_signed(5);

        extract_schema gen{"id", {}, {}, {}, false, true};

        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto output = gen.eval_impl(
            {.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
        EXPECT_SCHEMA_EQ(output.ref(), R"([4])");
    }
    {
        owned_object input = test::ddwaf_object_da::make_signed(-5);

        extract_schema gen{"id", {}, {}, {}, false, true};

        ddwaf::timer deadline{2s};
        processor_cache cache;
        auto output = gen.eval_impl(
            {.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
        EXPECT_SCHEMA_EQ(output.ref(), R"([4])");
    }
}

TEST(TestExtractSchema, StringScalarSchema)
{
    auto *alloc = memory::get_default_resource();

    owned_object input = test::ddwaf_object_da::make_string("string");

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([8])");
}

TEST(TestExtractSchema, FloatScalarSchema)
{
    auto *alloc = memory::get_default_resource();

    owned_object input = test::ddwaf_object_da::make_float(1.5);

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([16])");
}

TEST(TestExtractSchema, EmptyArraySchema)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::array();

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([[],{"len":0}])");
}

TEST(TestExtractSchema, ArraySchema)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::array({test::ddwaf_object_da::make_signed(22), "string",
        owned_object{}, owned_object::make_null()});

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([[[1],[0],[8],[4]],{"len":4}])");
}

TEST(TestExtractSchema, ArrayWithDuplicateScalarSchema)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::array({"string", "string", "string", "string"});

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([[[8]],{"len":4}])");
}

TEST(TestExtractSchema, ArrayWithDuplicateMapsSchema)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::array(
        {object_builder_da::map(
             {{"unsigned", test::ddwaf_object_da::make_signed(5)}, {"string", "str"}}),
            object_builder_da::map({{"signed", test::ddwaf_object_da::make_signed(-5)}}),
            object_builder_da::map({{"unsigned", test::ddwaf_object_da::make_signed(5)}}),
            object_builder_da::map(
                {{"unsigned", test::ddwaf_object_da::make_signed(109)}, {"string", "wahtever"}})});

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(),
        R"([[[{"unsigned":[4]}],[{"signed":[4]}],[{"string":[8],"unsigned":[4]}]],{"len":4}])");
}

TEST(TestExtractSchema, ArrayWithDuplicateArraysSchema)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::array(
        {object_builder_da::array({test::ddwaf_object_da::make_signed(5), "str"}),
            object_builder_da::array({test::ddwaf_object_da::make_signed(-5)}),
            object_builder_da::array({test::ddwaf_object_da::make_signed(5)}),
            object_builder_da::array({test::ddwaf_object_da::make_signed(109), "wahtever"})});

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([[[[[4]],{"len":1}],[[[8],[4]],{"len":2}]],{"len":4}])");
}

TEST(TestExtractSchema, ArrayWithDuplicateContainersSchema)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::array(
        {object_builder_da::map(
             {{"unsigned", test::ddwaf_object_da::make_signed(5)}, {"string", "str"}}),
            object_builder_da::array({test::ddwaf_object_da::make_signed(-5)}),
            object_builder_da::array({test::ddwaf_object_da::make_signed(5)}),
            object_builder_da::map(
                {{"string", "wahtever"}, {"unsigned", test::ddwaf_object_da::make_signed(109)}})});

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(
        output.ref(), R"([[[[[4]],{"len":1}],[{"string":[8],"unsigned":[4]}]],{"len":4}])");
}

TEST(TestExtractSchema, EmptyMapSchema)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::map();

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([{}])");
}

TEST(TestExtractSchema, MapSchema)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::map({{"unsigned", test::ddwaf_object_da::make_signed(22)},
        {"string", "string"}, {"invalid", owned_object{}}, {"null", owned_object::make_null()},
        {"map", object_builder_da::map(
                    {{"unsigned", test::ddwaf_object_da::make_signed(5)}, {"string", "str"}})},
        {"array", object_builder_da::array({test::ddwaf_object_da::make_signed(-5)})}});

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(),
        R"([{"array":[[[4]],{"len":1}],"invalid":[0],"map":[{"unsigned":[4],"string":[8]}],"null":[1],"string":[8],"unsigned":[4]}])");
}

TEST(TestExtractSchema, DepthLimit)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::array();
    borrowed_object parent{input};
    for (unsigned i = 0; i < extract_schema::max_container_depth + 10; ++i) {
        parent = parent.emplace_back(object_builder_da::array());
    }

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(),
        R"([[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}]],{"len":1}])");
}

TEST(TestExtractSchema, ArrayNodesLimit)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::array();
    for (unsigned i = 0; i < extract_schema::max_array_nodes + 10; ++i) {
        input.emplace_back(object_builder_da::array());
    }

    extract_schema gen{"id", {}, {}, {}, false, true};
    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([[[[],{"len":0}]],{"len":20,"truncated":true}])");
}

TEST(TestExtractSchema, RecordNodesLimit)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::map();
    for (unsigned i = 0; i < extract_schema::max_record_nodes + 10; ++i) {
        input.emplace("child", object_builder_da::array());
    }

    extract_schema gen{"id", {}, {}, {}, false, true};
    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([{"child":[[],{"len":0}]},{"truncated":true}])");
}

TEST(TestExtractSchema, SchemaWithSingleScanner)
{
    auto *alloc = memory::get_default_resource();

    owned_object input = test::ddwaf_object_da::make_string("string");

    scanner scnr{"0", {{"type", "PII"}, {"category", "IP"}}, nullptr,
        std::make_unique<matcher::regex_match>("string", 6, true)};

    extract_schema gen{"id", {}, {}, {&scnr}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([8,{"type":"PII","category":"IP"}])");
}

TEST(TestExtractSchema, SchemaWithMultipleScanners)
{
    auto *alloc = memory::get_default_resource();

    owned_object input = test::ddwaf_object_da::make_string("string");

    scanner scnr0{"0", {{"type", "PII"}, {"category", "first"}}, nullptr,
        std::make_unique<matcher::regex_match>("strong", 6, true)};
    scanner scnr1{"1", {{"type", "PII"}, {"category", "second"}}, nullptr,
        std::make_unique<matcher::regex_match>("string", 6, true)};
    scanner scnr2{"2", {{"type", "PII"}, {"category", "third"}}, nullptr,
        std::make_unique<matcher::regex_match>("stng", 4, true)};

    extract_schema gen{"id", {}, {}, {&scnr0, &scnr1, &scnr2}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([8,{"type":"PII","category":"second"}])");
}

TEST(TestExtractSchema, SchemaWithScannerNoMatch)
{
    auto *alloc = memory::get_default_resource();

    owned_object input = test::ddwaf_object_da::make_string("string");

    scanner scnr0{"0", {{"type", "PII"}, {"category", "first"}}, nullptr,
        std::make_unique<matcher::regex_match>("strong", 6, true)};
    scanner scnr1{"1", {{"type", "PII"}, {"category", "second"}}, nullptr,
        std::make_unique<matcher::regex_match>("strange", 7, true)};
    scanner scnr2{"2", {{"type", "PII"}, {"category", "third"}}, nullptr,
        std::make_unique<matcher::regex_match>("what", 4, true)};

    extract_schema gen{"id", {}, {}, {&scnr0, &scnr1, &scnr2}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([8])");
}

TEST(TestExtractSchema, SchemaWithScannerSingleValueNoKey)
{
    auto *alloc = memory::get_default_resource();

    owned_object input = test::ddwaf_object_da::make_string("string");

    scanner scnr{"0", {{"type", "PII"}, {"category", "IP"}},
        std::make_unique<matcher::regex_match>("string", 6, true),
        std::make_unique<matcher::regex_match>("string", 6, true)};

    extract_schema gen{"id", {}, {}, {&scnr}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([8])");
}

TEST(TestExtractSchema, SchemaWithScannerArrayNoKey)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::array({"string"});

    scanner scnr{"0", {{"type", "PII"}, {"category", "IP"}},
        std::make_unique<matcher::regex_match>("string", 6, true),
        std::make_unique<matcher::regex_match>("string", 6, true)};

    extract_schema gen{"id", {}, {}, {&scnr}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([[[8]],{"len":1}])");
}

TEST(TestExtractSchema, SchemaWithScannerArrayWithKey)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::map({{"string", object_builder_da::array({"string"})}});

    scanner scnr{"0", {{"type", "PII"}, {"category", "IP"}},
        std::make_unique<matcher::regex_match>("string", 6, true),
        std::make_unique<matcher::regex_match>("string", 6, true)};

    extract_schema gen{"id", {}, {}, {&scnr}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(
        output.ref(), R"([{"string":[[[8,{"category":"IP","type":"PII"}]],{"len":1}]}])");
}

TEST(TestExtractSchema, SchemaWithScannerNestedArrayWithKey)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::map(
        {{"string", object_builder_da::array({object_builder_da::array({"string"})})}});

    scanner scnr{"0", {{"type", "PII"}, {"category", "IP"}},
        std::make_unique<matcher::regex_match>("string", 6, true),
        std::make_unique<matcher::regex_match>("string", 6, true)};

    extract_schema gen{"id", {}, {}, {&scnr}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(),
        R"([{"string":[[[[[8,{"category":"IP","type":"PII"}]],{"len":1}]],{"len":1}]}])");
}

} // namespace
