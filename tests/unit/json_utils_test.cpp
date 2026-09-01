// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include <string>
#include <string_view>

#include "json_utils.hpp"

#include "common/gtest_utils.hpp"

using namespace ddwaf;
using namespace ddwaf::test;

namespace {

owned_object truncated_json_to_object(std::string_view json)
{
    return ddwaf::json_to_object(
        json, memory::get_default_resource(), json_parse_mode::truncated_prefix);
}

TEST(TestJsonUtils, Empty)
{
    auto object = ddwaf::json_to_object("");
    EXPECT_EQ(object.type(), object_type::invalid);
}

TEST(TestJsonUtils, Null)
{
    auto object = ddwaf::json_to_object("null");
    EXPECT_EQ(object.type(), object_type::null);
}

TEST(TestJsonUtils, Boolean)
{
    {
        auto object = ddwaf::json_to_object("true");
        EXPECT_EQ(object.type(), object_type::boolean);
        EXPECT_EQ(object.as<bool>(), true);
    }

    {
        auto object = ddwaf::json_to_object("false");
        EXPECT_EQ(object.type(), object_type::boolean);
        EXPECT_EQ(object.as<bool>(), false);
    }
}

TEST(TestJsonUtils, Signed)
{
    auto object = ddwaf::json_to_object("-5");
    EXPECT_EQ(object.type(), object_type::int64);
    EXPECT_EQ(object.as<int64_t>(), -5);
}

TEST(TestJsonUtils, Unsigned)
{
    auto object = ddwaf::json_to_object("18446744073709551615");
    EXPECT_EQ(object.type(), object_type::uint64);
    EXPECT_EQ(object.as<uint64_t>(), 18446744073709551615ULL);
}

TEST(TestJsonUtils, Double)
{
    auto object = ddwaf::json_to_object("5.5");
    EXPECT_EQ(object.type(), object_type::float64);
    EXPECT_EQ(object.as<double>(), 5.5);
}

TEST(TestJsonUtils, String)
{
    auto object = ddwaf::json_to_object("\"this is a string\"");
    EXPECT_TRUE(object.is_string());

    EXPECT_STRV(object.as<std::string_view>(), "this is a string");
}

TEST(TestJsonUtils, EmptyArray)
{
    auto object = ddwaf::json_to_object("[]");
    EXPECT_EQ(object.type(), object_type::array);
    EXPECT_EQ(object.size(), 0);
}

TEST(TestJsonUtils, ArrayOfScalars)
{
    auto object = ddwaf::json_to_object("[null, true, -1, 18446744073709551615, 1.2, \"string\"]");
    EXPECT_EQ(object.type(), object_type::array);
    EXPECT_EQ(object.size(), 6);

    EXPECT_EQ(object.at(0).type(), object_type::null);

    EXPECT_EQ(object.at(1).type(), object_type::boolean);
    EXPECT_EQ(object.at(1).as<bool>(), true);

    EXPECT_EQ(object.at(2).type(), object_type::int64);
    EXPECT_EQ(object.at(2).as<int64_t>(), -1);

    EXPECT_EQ(object.at(3).type(), object_type::uint64);
    EXPECT_EQ(object.at(3).as<uint64_t>(), 18446744073709551615ULL);

    EXPECT_EQ(object.at(4).type(), object_type::float64);
    EXPECT_EQ(object.at(4).as<double>(), 1.2);

    EXPECT_TRUE(object.at(5).is_string());
    EXPECT_STRV(object.at(5).as<std::string_view>(), "string");
}

TEST(TestJsonUtils, NestedArray)
{
    std::string json_str =
        R"([null,true,-1,18446744073709551615,1.2,"string",["array",["array"],{"map":true}],{"map":{"map":-42},"array":["array",{"map":1729}]}])";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object.ref(), json_str);
}

TEST(TestJsonUtils, NestedEmptyArraysHardcodedLimit)
{
    std::string json_str = R"([[[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]]])";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object.ref(), R"([[[[[[[[[[[[[[[[[[[[[]]]]]]]]]]]]]]]]]]]]])");
}

TEST(TestJsonUtils, EmptyMap)
{
    auto object = ddwaf::json_to_object("{}");
    EXPECT_EQ(object.type(), object_type::map);
    EXPECT_EQ(object.size(), 0);
}

TEST(TestJsonUtils, MapOfScalars)
{
    auto object = ddwaf::json_to_object(
        R"({"null":null,"bool":true,"int":-1,"uint":18446744073709551615,"double":1.2,"string":"string"})");
    EXPECT_EQ(object.type(), object_type::map);
    EXPECT_EQ(object.size(), 6);

    object_view view = object;
    {
        auto [key, child] = view.at(0);
        EXPECT_EQ(child.type(), object_type::null);

        EXPECT_STRV(key.as<std::string_view>(), "null");
    }

    {
        auto [key, child] = view.at(1);
        EXPECT_EQ(child.type(), object_type::boolean);
        EXPECT_EQ(child.as<bool>(), true);

        EXPECT_STRV(key.as<std::string_view>(), "bool");
    }

    {
        auto [key, child] = view.at(2);
        EXPECT_EQ(child.type(), object_type::int64);
        EXPECT_EQ(child.as<int64_t>(), -1);

        EXPECT_STRV(key.as<std::string_view>(), "int");
    }

    {
        auto [key, child] = view.at(3);
        EXPECT_EQ(child.type(), object_type::uint64);
        EXPECT_EQ(child.as<uint64_t>(), 18446744073709551615ULL);

        EXPECT_STRV(key.as<std::string_view>(), "uint");
    }

    {
        auto [key, child] = view.at(4);
        EXPECT_EQ(child.type(), object_type::float64);
        EXPECT_EQ(child.as<double>(), 1.2);

        EXPECT_STRV(key.as<std::string_view>(), "double");
    }

    {
        auto [key, child] = view.at(5);
        EXPECT_TRUE(child.is_string());
        EXPECT_STRV(child.as<std::string_view>(), "string");

        EXPECT_STRV(key.as<std::string_view>(), "string");
    }
}

TEST(TestJsonUtils, NestedMap)
{
    std::string json_str =
        R"({"null":null,"bool":true,"int":-1,"uint":18446744073709551615,"double":1.2,"string":"string","array":["array",["array"],{"map":true}],"map":{"map":{"map":-42},"array":["array",{"map":1729}]}})";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object.ref(), json_str);
}

TEST(TestJsonUtils, NestedEmptyMapsHardcodedLimit)
{
    std::string json_str =
        R"({"0":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"15":{"16":{"17":{"18":{"19":{"20":{}}}}}}}}}}}}}}}}}}}}}})";
    auto object = ddwaf::json_to_object(json_str);

    // If the JSON is reversible...
    EXPECT_JSON(object.ref(),
        R"({"0":{"1":{"2":{"3":{"4":{"5":{"6":{"7":{"8":{"9":{"10":{"11":{"12":{"13":{"14":{"15":{"16":{"17":{"18":{"19":{}}}}}}}}}}}}}}}}}}}}})");
}

TEST(TestJsonUtils, InvalidJson)
{
    std::string json_str =
        R"([null,true,-1,18446744073709551615,1.2,"string",["array",["array"],{"map":true}],{"map":{"map":-42},"array":])";

    auto object = ddwaf::json_to_object(json_str);
    EXPECT_EQ(object.type(), object_type::invalid);
}

TEST(TestJsonUtils, TruncatedJsonFinalizesContainers)
{
    struct test_case {
        std::string_view prefix;
        const char *expected;
    };
    constexpr test_case cases[] = {
        {R"({"first":1,"nested":[2,{"keep":true)", R"({"first":1,"nested":[2,{"keep":true}]})"},
        {R"({"kept":1,"drop)", R"({"kept":1})"},
        {R"({"kept":1,"drop":)", R"({"kept":1})"},
        {"{\"kept\":1,\"drop\"", R"({"kept":1})"},
        {"[1,2,", "[1,2]"},
        {"[tru", "[]"},
        {"[1.", "[]"},
        {"[1e+", "[]"},
    };

    for (const auto &[prefix, expected] : cases) {
        SCOPED_TRACE(prefix);
        auto object = truncated_json_to_object(prefix);
        EXPECT_JSON_EXACT(object.ref(), expected);
    }
}

TEST(TestJsonUtils, TruncatedJsonTerminalNumbers)
{
    struct test_case {
        std::string_view prefix;
        const char *expected;
    };
    constexpr test_case cases[] = {
        {"[12", "[12]"},
        {"[12,", "[12]"},
        {"[-12", "[-12]"},
        {"[0", "[0]"},
        {"[1e3", "[1000.0]"},
        {"[12345678901234567", "[12345678901234567]"},
        // Incomplete numbers are discarded rather than guessed at.
        {"[12.", "[]"},
        {"[-", "[]"},
        {"[1e", "[]"},
        {"[1e+", "[]"},
    };

    for (const auto &[prefix, expected] : cases) {
        SCOPED_TRACE(prefix);
        auto object = truncated_json_to_object(prefix);
        EXPECT_JSON_EXACT(object.ref(), expected);
    }
}

TEST(TestJsonUtils, TruncatedJsonRecoversStrings)
{
    struct test_case {
        std::string_view prefix;
        const char *expected;
    };
    constexpr test_case cases[] = {
        {R"(["hello world)", R"(["hello world"])"},
        {R"(["a\"b)", R"(["a\"b"])"},
        {R"json(["hello\)json", R"(["hello"])"},
        {R"(["hello\u12)", R"(["hello"])"},
        {R"(["hello\uD83D)", R"(["hello"])"},
        {R"(["hello\uD83D\uD)", R"(["hello"])"},
        {R"(["hello\uD83D\uDE0)", R"(["hello"])"},
    };

    for (const auto &[prefix, expected] : cases) {
        SCOPED_TRACE(prefix);
        auto object = truncated_json_to_object(prefix);
        EXPECT_JSON_EXACT(object.ref(), expected);
    }

    auto root = truncated_json_to_object(R"("root value)");
    ASSERT_TRUE(root.is_string());
    EXPECT_STRV(root.as<std::string_view>(), "root value");
}

TEST(TestJsonUtils, TruncatedJsonDropsIncompleteUtf8)
{
    std::string json = R"(["caf)";
    json.push_back(static_cast<char>(0xC3));

    auto object = truncated_json_to_object(json);
    EXPECT_JSON(object.ref(), R"(["caf"])");
}

TEST(TestJsonUtils, TruncatedJsonValidatesUtf8Encoding)
{
    // The truncated-prefix parser validates the UTF-8 encoding of the input,
    // which is what prevents a truncated multibyte sequence from recovering
    // into an overlong or surrogate code point. The strict parser does not
    // validate the encoding and accepts raw invalid UTF-8 bytes as-is.
    const std::string cases[] = {
        // Invalid lead byte followed by a non-continuation byte.
        "[\"\xC3\"]",
        // Three-byte encoding of the surrogate code point U+D800.
        "[\"\xED\xA0\x80\"]",
        // Four-byte encoding of a code point above U+10FFFF.
        "[\"\xF4\x90\x80\x80\"]",
    };

    for (const auto &json : cases) {
        EXPECT_TRUE(truncated_json_to_object(json).is_invalid());
        EXPECT_FALSE(ddwaf::json_to_object(json).is_invalid());
    }
}

TEST(TestJsonUtils, TruncatedJsonRejectsMalformedPrefix)
{
    constexpr std::string_view malformed_prefixes[] = {
        R"({"key":invalid)",
        R"([1 2)",
        R"(["bad\x)",
        R"(["bad\uDC00)",
        R"(["bad\uD83D\u0041)",
        R"({"key":1}x)",
        R"([truX)",
        R"([1eX)",
    };
    for (const auto prefix : malformed_prefixes) {
        SCOPED_TRACE(prefix);
        EXPECT_TRUE(truncated_json_to_object(prefix).is_invalid());
    }

    std::string invalid_utf8 = R"(["bad)";
    invalid_utf8.push_back(static_cast<char>(0x80));
    EXPECT_TRUE(truncated_json_to_object(invalid_utf8).is_invalid());

    invalid_utf8 = R"(["bad)";
    invalid_utf8.push_back(static_cast<char>(0xF0));
    invalid_utf8.push_back(static_cast<char>(0x80));
    EXPECT_TRUE(truncated_json_to_object(invalid_utf8).is_invalid());
}

TEST(TestJsonUtils, TruncatedJsonRequiresUsefulRoot)
{
    constexpr std::string_view incomplete_roots[] = {"", "   ", "tru", "1e"};
    for (const auto prefix : incomplete_roots) {
        SCOPED_TRACE(prefix);
        EXPECT_TRUE(truncated_json_to_object(prefix).is_invalid());
    }
}

TEST(TestJsonUtils, TruncatedJsonAcceptsCompleteInput)
{
    auto object = truncated_json_to_object(R"({"key":[1,"value"]})");
    EXPECT_JSON(object.ref(), R"({"key":[1,"value"]})");
}

TEST(TestJsonUtils, TruncatedJsonAcceptsEveryPrefixOfValidContainer)
{
    const std::string json =
        R"({"escaped":"a\"b\\c\n","unicode":"\uD83D\uDE00","utf8":"café € 😀","numbers":[0,-1,1.25e+10,true,false,null],"nested":{"array":[{"key":"value"}]}})";

    for (std::size_t length = 1; length <= json.size(); ++length) {
        auto object = truncated_json_to_object(std::string_view(json).substr(0, length));
        EXPECT_FALSE(object.is_invalid()) << "prefix length " << length;
    }
}

TEST(TestJsonUtils, JsonRejectsEmbeddedNul)
{
    const std::string cases[] = {
        std::string(R"({"ok":1})") + '\0' + "garbage",
        std::string(R"({"ok":1})") + '\0',
        std::string("[\"a") + '\0' + "b\"]",
        std::string("[\"a") + '\0',
    };

    for (const auto &json : cases) {
        EXPECT_TRUE(ddwaf::json_to_object(json).is_invalid());
        EXPECT_TRUE(truncated_json_to_object(json).is_invalid());
    }

    // The same documents without the NUL byte are accepted.
    EXPECT_FALSE(ddwaf::json_to_object(R"({"ok":1})").is_invalid());
    EXPECT_FALSE(truncated_json_to_object(R"({"ok":1})").is_invalid());
}

TEST(TestJsonUtils, TruncatedJsonRejectsImpossibleSurrogatePrefixes)
{
    // A standalone escape cut off mid-digits is only recoverable if the digits
    // can still complete to something other than a low surrogate; a high
    // surrogate may still be completed by a later low surrogate.
    constexpr std::string_view impossible_standalone[] = {
        R"(["\uDC)",
        R"(["\uDC0)",
        R"(["\uDF)",
        R"(["\uDCAF)",
    };
    for (const auto prefix : impossible_standalone) {
        SCOPED_TRACE(prefix);
        EXPECT_TRUE(truncated_json_to_object(prefix).is_invalid());
    }

    constexpr std::string_view possible_standalone[] = {
        R"(["\uD)",
        R"(["\uD8)",
        R"(["\uD7)",
        R"(["\uE)",
        R"(["\uD83D)",
    };
    for (const auto prefix : possible_standalone) {
        SCOPED_TRACE(prefix);
        EXPECT_FALSE(truncated_json_to_object(prefix).is_invalid());
    }

    // An escape cut off after a high surrogate is only recoverable if the
    // digits can still complete into a low surrogate.
    constexpr std::string_view impossible_pair[] = {
        R"(["\uD83D\uE)",
        R"(["\uD83D\uDA)",
        R"(["\uD83D\uDB)",
        R"(["\uD83D\uD9)",
        R"(["\uD83D\uD0)",
        R"(["\uD83D\uD8)",
        R"(["\uD83D\u00)",
    };
    for (const auto prefix : impossible_pair) {
        SCOPED_TRACE(prefix);
        EXPECT_TRUE(truncated_json_to_object(prefix).is_invalid());
    }

    constexpr std::string_view possible_pair[] = {
        R"(["\uD83D\uD)",
        R"(["\uD83D\uDC)",
        R"(["\uD83D\u)",
        R"(["\uD83D\uDE0)",
    };
    for (const auto prefix : possible_pair) {
        SCOPED_TRACE(prefix);
        EXPECT_FALSE(truncated_json_to_object(prefix).is_invalid());
    }
}

TEST(TestJsonUtils, TruncatedJsonRejectsExcessiveNesting)
{
    // Up to 20 levels of nesting are accepted, finalized or not.
    EXPECT_FALSE(
        truncated_json_to_object(std::string(20, '[') + "1" + std::string(20, ']')).is_invalid());
    EXPECT_FALSE(truncated_json_to_object(std::string(20, '[') + "1").is_invalid());

    // Beyond the limit the parse fails rather than silently dropping content.
    EXPECT_TRUE(
        truncated_json_to_object(std::string(21, '[') + "1" + std::string(21, ']')).is_invalid());
    EXPECT_TRUE(truncated_json_to_object(std::string(21, '[') + "1").is_invalid());

    std::string deep_map;
    for (std::size_t i = 0; i < 21; ++i) { deep_map += R"({"a":)"; }
    deep_map += "1";
    EXPECT_TRUE(truncated_json_to_object(deep_map).is_invalid());

    deep_map.clear();
    for (std::size_t i = 0; i < 20; ++i) { deep_map += R"({"a":)"; }
    deep_map += "1";
    EXPECT_FALSE(truncated_json_to_object(deep_map).is_invalid());
}

TEST(TestJsonUtils, TruncatedJsonParsesLargeContainers)
{
    // Arrays and maps around the large-representation promotion boundary.
    for (std::size_t count : {65535, 65536, 65537}) {
        SCOPED_TRACE(count);
        std::string json;
        json.reserve(count * 2 + 2);
        json.push_back('[');
        for (std::size_t i = 0; i < count; ++i) {
            if (i != 0) {
                json.push_back(',');
            }
            json.push_back(static_cast<char>('0' + (i % 10)));
        }
        json.push_back(']');

        auto object = truncated_json_to_object(json);
        ASSERT_FALSE(object.is_invalid());
        EXPECT_EQ(object.size(), count);
        EXPECT_EQ(object.at(0).as<int64_t>(), 0);
        EXPECT_EQ(object.at(count - 1).as<int64_t>(), static_cast<int64_t>((count - 1) % 10));
    }

    std::string json;
    json.push_back('{');
    for (std::size_t i = 0; i < 65536; ++i) {
        if (i != 0) {
            json.push_back(',');
        }
        json += "\"key" + std::to_string(i) + "\":" + std::to_string(i % 10);
    }
    json.push_back('}');

    auto object = truncated_json_to_object(json);
    ASSERT_FALSE(object.is_invalid());
    EXPECT_EQ(object.size(), 65536);
}

} // namespace
