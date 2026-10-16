// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2023 Datadog, Inc.

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"
#include "exception.hpp"
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

TEST(TestExtractSchema, ArrayWithDuplicateTaggedScalarsFromDifferentScanners)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::map({{"key",
        object_builder_da::array({"first", "second", "first", "untagged", "second", "other"})}});

    // Both scanners have the same tags, so their nodes are equal
    scanner scnr0{"0", {{"type", "PII"}, {"category", "IP"}}, nullptr,
        std::make_unique<matcher::regex_match>("^first$", 1, true)};
    scanner scnr1{"1", {{"type", "PII"}, {"category", "IP"}}, nullptr,
        std::make_unique<matcher::regex_match>("^second$", 1, true)};
    scanner scnr2{"2", {{"type", "PII"}, {"category", "other"}}, nullptr,
        std::make_unique<matcher::regex_match>("^other$", 1, true)};

    extract_schema gen{"id", {}, {}, {&scnr0, &scnr1, &scnr2}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(),
        R"([{"key":[[[8],[8,{"category":"IP","type":"PII"}],[8,{"category":"other","type":"PII"}]],{"len":6}]}])");
}

TEST(TestExtractSchema, ScannerWithoutTagsEqualsUntaggedScalar)
{
    auto *alloc = memory::get_default_resource();

    auto input = object_builder_da::array({"tagless", "string"});

    scanner scnr{"0", {}, nullptr, std::make_unique<matcher::regex_match>("^tagless$", 1, true)};

    extract_schema gen{"id", {}, {}, {&scnr}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);
    EXPECT_SCHEMA_EQ(output.ref(), R"([[[8]],{"len":2}])");
}

TEST(TestExtractSchema, LargeSchemaSpanningMultipleArenaBlocks)
{
    auto *alloc = memory::get_default_resource();

    // 255 records of 10 arrays each, with distinct keys, is enough to need
    // several arena blocks for the schema tree
    auto input = owned_object::make_map(0, alloc);
    for (unsigned i = 0; i < extract_schema::max_record_nodes; ++i) {
        auto child = input.emplace("key" + std::to_string(i), owned_object::make_map(0, alloc));
        for (unsigned j = 0; j < extract_schema::max_array_nodes; ++j) {
            auto array =
                child.emplace("item" + std::to_string(j), owned_object::make_array(0, alloc));
            array.emplace_back(owned_object::make_signed(j));
            array.emplace_back("value");
        }
    }

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{2s};
    processor_cache cache;
    auto output =
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline);

    const object_view schema{output};
    ASSERT_TRUE(schema.is_array());
    auto record = schema.at_value(0);
    ASSERT_TRUE(record.is_map());
    EXPECT_EQ(record.size(), extract_schema::max_record_nodes);
    for (unsigned i = 0; i < record.size(); ++i) {
        auto child = record.at_value(i).at_value(0);
        ASSERT_TRUE(child.is_map());
        EXPECT_EQ(child.size(), extract_schema::max_array_nodes);
    }
}

TEST(TestExtractSchema, TimeoutDuringGeneration)
{
    auto *alloc = memory::get_default_resource();

    auto input = owned_object::make_map(0, alloc);
    for (unsigned i = 0; i < extract_schema::max_record_nodes; ++i) {
        auto child = input.emplace("key" + std::to_string(i), owned_object::make_map(0, alloc));
        child.emplace("value", owned_object::make_array(0, alloc)).emplace_back("string");
    }

    extract_schema gen{"id", {}, {}, {}, false, true};

    ddwaf::timer deadline{0s};
    processor_cache cache;
    EXPECT_THROW(
        gen.eval_impl({.address = {}, .key_path = {}, .value = {input}}, cache, alloc, deadline),
        ddwaf::timeout_exception);
}

} // namespace
