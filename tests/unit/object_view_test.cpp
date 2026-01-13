// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"
#include "object.hpp"

using namespace ddwaf;
using namespace ddwaf::test;
using namespace std::literals;

namespace {

TEST(TestObjectView, DefaultObject)
{
    object_view view;
    EXPECT_FALSE(view.has_value());
}

TEST(TestObjectView, InvalidObject)
{
    owned_object original = owned_object{};
    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::invalid);

    EXPECT_EQ(view.ptr(), original.ptr());

    EXPECT_FALSE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<int64_t>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, NullObject)
{
    auto original = owned_object::make_null();

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::null);

    EXPECT_FALSE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<int64_t>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, BooleanObject)
{
    owned_object original = test::ddwaf_object_da::make_boolean(true);

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::boolean);

    EXPECT_FALSE(view.is_container());
    EXPECT_TRUE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_TRUE(view.is<bool>());
    EXPECT_EQ(view.as<bool>(), true);

    EXPECT_FALSE(view.is<int64_t>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, SignedObject)
{
    owned_object original = test::ddwaf_object_da::make_signed(-20);

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::int64);

    EXPECT_FALSE(view.is_container());
    EXPECT_TRUE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_TRUE(view.is<int64_t>());
    EXPECT_EQ(view.as<int64_t>(), -20);

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, SignedObjectCompatibility)
{
    {
        owned_object original = test::ddwaf_object_da::make_signed(-1);
        object_view view(original);

        EXPECT_TRUE(view.is<int8_t>());
        EXPECT_TRUE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original =
            test::ddwaf_object_da::make_signed(std::numeric_limits<int8_t>::min() - 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_TRUE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original =
            test::ddwaf_object_da::make_signed(std::numeric_limits<int8_t>::max() + 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_TRUE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original =
            test::ddwaf_object_da::make_signed(std::numeric_limits<int16_t>::min() - 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original =
            test::ddwaf_object_da::make_signed(std::numeric_limits<int16_t>::max() + 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_TRUE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original = test::ddwaf_object_da::make_signed(
            static_cast<int64_t>(std::numeric_limits<int32_t>::min()) - 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_FALSE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }

    {
        owned_object original = test::ddwaf_object_da::make_signed(
            static_cast<int64_t>(std::numeric_limits<int32_t>::max()) + 1);
        object_view view(original);

        EXPECT_FALSE(view.is<int8_t>());
        EXPECT_FALSE(view.is<int16_t>());
        EXPECT_FALSE(view.is<int32_t>());
        EXPECT_TRUE(view.is<int64_t>());
    }
}

TEST(TestObjectView, UnsignedObject)
{
    owned_object original = test::ddwaf_object_da::make_unsigned(20UL);
    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::uint64);

    EXPECT_FALSE(view.is_container());
    EXPECT_TRUE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_TRUE(view.is<uint64_t>());
    EXPECT_EQ(view.as<uint64_t>(), 20);

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<int64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, UnsignedObjectCompatibility)
{
    {
        owned_object original = test::ddwaf_object_da::make_unsigned(1UL);
        object_view view(original);

        EXPECT_TRUE(view.is<uint8_t>());
        EXPECT_TRUE(view.is<uint16_t>());
        EXPECT_TRUE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }

    {
        owned_object original = test::ddwaf_object_da::make_unsigned(
            static_cast<uint64_t>(std::numeric_limits<uint8_t>::max() + 1));
        object_view view(original);

        EXPECT_FALSE(view.is<uint8_t>());
        EXPECT_TRUE(view.is<uint16_t>());
        EXPECT_TRUE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }

    {
        owned_object original = test::ddwaf_object_da::make_unsigned(
            static_cast<uint64_t>(std::numeric_limits<uint16_t>::max() + 1));
        object_view view(original);

        EXPECT_FALSE(view.is<uint8_t>());
        EXPECT_FALSE(view.is<uint16_t>());
        EXPECT_TRUE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }

    {
        owned_object original = test::ddwaf_object_da::make_unsigned(
            static_cast<uint64_t>(std::numeric_limits<uint32_t>::max()) + 1);
        object_view view(original);

        EXPECT_FALSE(view.is<uint8_t>());
        EXPECT_FALSE(view.is<uint16_t>());
        EXPECT_FALSE(view.is<uint32_t>());
        EXPECT_TRUE(view.is<uint64_t>());
    }
}
TEST(TestObjectView, FloatObject)
{
    owned_object original = test::ddwaf_object_da::make_float(20.1);
    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::float64);

    EXPECT_FALSE(view.is_container());
    EXPECT_TRUE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_TRUE(view.is<double>());
    EXPECT_EQ(view.as<double>(), 20.1);

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<int64_t>());

    EXPECT_FALSE(view.is<std::string>());
    EXPECT_FALSE(view.is<std::string_view>());
    EXPECT_FALSE(view.is<const char *>());
}

TEST(TestObjectView, StringObject)
{
    owned_object original = test::ddwaf_object_da::make_string("string_value");

    object_view view(original);

    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.type(), object_type::small_string);

    EXPECT_EQ(view.size(), sizeof("string_value") - 1);
    EXPECT_FALSE(view.empty());
    EXPECT_FALSE(view.is_container());
    EXPECT_TRUE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_FALSE(view.is<bool>());
    EXPECT_FALSE(view.is<uint64_t>());
    EXPECT_FALSE(view.is<int64_t>());
    EXPECT_FALSE(view.is<double>());

    EXPECT_TRUE(view.is<std::string>());
    EXPECT_TRUE(view.is<std::string_view>());
    EXPECT_TRUE(view.is<const char *>());
}

TEST(TestObjectView, ArrayObject)
{
    auto root = test::ddwaf_object_da::make_array();
    for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i + 100)); }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::array);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_TRUE(view.is_array());

    for (unsigned i = 0; i < 20; i++) {
        auto expected_value = std::to_string(100 + i);
        {
            auto [key, value] = view.at(i);
            EXPECT_FALSE(key.has_value());
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto value = view.at_value(i);
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto key = view.at_key(i);
            EXPECT_FALSE(key.has_value());
        }
    }
}

TEST(TestObjectView, MapObject)
{
    auto root = test::ddwaf_object_da::make_map();
    for (unsigned i = 0; i < 20; i++) { root.emplace(std::to_string(i), std::to_string(i + 100)); }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::map);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_TRUE(view.is_map());
    EXPECT_FALSE(view.is_array());

    for (unsigned i = 0; i < 20; i++) {
        auto expected_key = std::to_string(i);
        auto expected_value = std::to_string(100 + i);
        {
            auto [key, value] = view.at(i);
            EXPECT_EQ(key.as<std::string_view>(), expected_key);
            EXPECT_EQ(value.as<std::string_view>(), expected_value);
        }

        {
            auto value = view.at_value(i);
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto key = view.at_key(i);
            EXPECT_EQ(key.as<std::string_view>(), expected_key);
        }
    }
}

TEST(TestObjectView, Equality)
{
    owned_object root = owned_object{};
    object_view view(root);

    {
        object_view view2(root);
        EXPECT_TRUE(view == view2);
        EXPECT_TRUE(view2 == view);
    }

    {
        owned_object other = owned_object{};
        object_view view2(other);

        EXPECT_FALSE(view == view2);
        EXPECT_FALSE(view2 == view);
    }

    {
        object_view view2;
        EXPECT_FALSE(view == view2);
        EXPECT_FALSE(view2 == view);
    }
}

TEST(TestObjectView, Inequality)
{
    owned_object root = owned_object{};
    object_view view(root);

    {
        object_view view2(root);
        EXPECT_FALSE(view != view2);
        EXPECT_FALSE(view2 != view);
    }

    {
        owned_object other = owned_object{};
        object_view view2(other);

        EXPECT_TRUE(view != view2);
        EXPECT_TRUE(view2 != view);
    }

    {
        object_view view2;
        EXPECT_TRUE(view != view2);
        EXPECT_TRUE(view2 != view);
    }
}

TEST(TestObjectView, StringEquality)
{
    owned_object root = test::ddwaf_object_da::make_string("something");

    object_view view(root);

    EXPECT_TRUE(view == "something"sv);
    EXPECT_FALSE(view == "something else"sv);
}

TEST(TestObjectView, StringInequality)
{
    owned_object root = test::ddwaf_object_da::make_string("something");

    object_view view(root);

    EXPECT_TRUE(view != "something else"sv);
    EXPECT_FALSE(view != "something"sv);
}

TEST(TestObjectView, StringComparisonEdgeCases)
{
    // Default (no value) view comparisons to string
    object_view empty_view;
    EXPECT_FALSE(empty_view == "anything"sv);
    EXPECT_FALSE(empty_view != "anything"sv);

    // Non-string object compared to string
    owned_object boolean_obj = owned_object::make_boolean(true);
    object_view bool_view{boolean_obj};
    EXPECT_FALSE(bool_view == "true"sv);
    EXPECT_TRUE(bool_view != "true"sv);
}

TEST(TestObjectView, BooleanObjectStringConversion)
{
    {
        owned_object original = owned_object::make_boolean(true);
        object_view view(original);
        auto converted = view.convert<std::string>();
        EXPECT_STR(converted, "true");
    }

    {
        owned_object original = owned_object::make_boolean(false);
        object_view view(original);
        auto converted = view.convert<std::string>();
        EXPECT_STR(converted, "false");
    }
}

TEST(TestObjectView, SignedObjectStringConversion)
{
    owned_object original = test::ddwaf_object_da::make_signed(-123456);
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "-123456");
}

TEST(TestObjectView, UnsignedObjectStringConversion)
{
    owned_object original = test::ddwaf_object_da::make_unsigned(123456UL);
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "123456");
}

TEST(TestObjectView, FloatObjectStringConversion)
{
    owned_object original = test::ddwaf_object_da::make_float(20.1);
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "20.1");
}

TEST(TestObjectView, StringtObjectStringConversion)
{
    owned_object original = test::ddwaf_object_da::make_string("this is a string");
    object_view view(original);
    auto converted = view.convert<std::string>();
    EXPECT_STR(converted, "this is a string");
}

TEST(TestObjectView, LiteralAndLongStringHandling)
{
    // Literal string keeps pointer, size path for literal_string
    constexpr const char literal[] = "literal-const-string";
    auto lit_obj = owned_object::make_string_literal(literal, sizeof(literal) - 1);
    object_view lit_view{lit_obj};
    ASSERT_TRUE(lit_view.is_string());
    EXPECT_EQ(lit_view.type(), object_type::literal_string);
    EXPECT_EQ(lit_view.size(), sizeof(literal) - 1);
    EXPECT_STREQ(lit_view.as<const char *>(), literal);
    EXPECT_EQ(lit_view.data(), literal);

    // Long string uses heap path (object_type::string), pointer differs from source buffer
    const std::string long_src(40, 'x');
    auto long_obj = test::ddwaf_object_da::make_string(std::string_view{long_src});
    object_view long_view{long_obj};
    ASSERT_TRUE(long_view.is_string());
    EXPECT_EQ(long_view.type(), object_type::string);
    EXPECT_EQ(long_view.size(), long_src.size());
    EXPECT_EQ(long_view.as<std::string_view>(), std::string_view{long_src});
    EXPECT_NE(long_view.data(), long_src.data());
}

TEST(TestObjectView, AsOrDefault)
{
    owned_object original = owned_object{};
    object_view view(original);

    EXPECT_EQ(view.as_or_default<std::string_view>({}), std::string_view{});
    EXPECT_EQ(view.as_or_default<double>(20.1), 20.1);
    EXPECT_EQ(view.as_or_default<uint64_t>(0), 0);
    EXPECT_EQ(view.as_or_default<int64_t>(0), 0);
    EXPECT_EQ(view.as_or_default<bool>(false), false);
}

TEST(TestObjectView, AsOrDefaultReturnsActual)
{
    owned_object original_true = owned_object::make_boolean(true);
    object_view view_true{original_true};
    EXPECT_TRUE(view_true.as_or_default<bool>(false));

    auto str_obj = owned_object::make_string_literal("abc", 3);
    object_view str_view{str_obj};
    EXPECT_EQ(str_view.as_or_default<std::string_view>(""), std::string_view{"abc"});
}

TEST(TestObjectView, KeyPathAccess)
{
    auto root = object_builder_da::map({
        {"1", object_builder_da::map({{"1.2", test::ddwaf_object_da::make_signed(111)},
                  {"1.3", test::ddwaf_object_da::make_signed(123)}})},
        {"2", object_builder_da::map({{"2.1",
                  object_builder_da::map({{"2.1.1", test::ddwaf_object_da::make_signed(9)}})}})},
        {"3", object_builder_da::array({"3.1"})},
    });

    object_view view(root);
    EXPECT_EQ(view.size(), 3);
    EXPECT_FALSE(view.empty());

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"1"};
        EXPECT_TRUE(view.find_key_path(key_path).is_map());
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"1", "1.2"};
        EXPECT_EQ(view.find_key_path(key_path).as<int64_t>(), 111);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"1", "1.3"};
        EXPECT_EQ(view.find_key_path(key_path).as<int64_t>(), 123);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"2"};
        EXPECT_TRUE(view.find_key_path(key_path).is_map());
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"2", "2.1"};
        EXPECT_TRUE(view.find_key_path(key_path).is_map());
    }
    {
        std::vector<std::variant<std::string, int64_t>> key_path{"2", "2.1", "2.1.1"};
        EXPECT_EQ(view.find_key_path(key_path).as<int64_t>(), 9);
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"3", "3.1"};
        EXPECT_FALSE(view.find_key_path(key_path).has_value());
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"4"};
        EXPECT_FALSE(view.find_key_path(key_path).has_value());
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"1", "key"};
        EXPECT_FALSE(view.find_key_path(key_path).has_value());
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{0};
        EXPECT_FALSE(view.find_key_path(key_path).has_value());
    }

    {
        std::vector<std::variant<std::string, int64_t>> key_path{"3", "3.1", "3.1.1"};
        EXPECT_FALSE(view.find_key_path(key_path).has_value());
    }
}

TEST(TestObjectView, FindKeyPathEmptyAndExcluded)
{
    // Build a nested structure: { "a": { "b": ["x","y"] } }
    auto root_obj = object_builder_da::map({
        {"a", object_builder_da::map({{"b", object_builder_da::array({"x", "y"})}})},
    });
    object_view root{root_obj};

    // Empty path should return the root
    std::vector<std::variant<std::string, int64_t>> empty_path;
    auto self = root.find_key_path(empty_path);
    EXPECT_TRUE(self.has_value());
    EXPECT_EQ(self.ptr(), root.ptr());

    // Excluding the root should immediately short-circuit
    std::unordered_set<object_cache_key> excluded_root{object_cache_key{root}};
    object_set_ref exclude_root{excluded_root};
    auto none1 = root.find_key_path(empty_path, exclude_root);
    EXPECT_FALSE(none1.has_value());

    // Excluding an intermediate node should short-circuit during traversal
    std::vector<std::variant<std::string, int64_t>> path_to_b{"a", "b"};
    auto b_node = root.find_key_path(path_to_b);
    ASSERT_TRUE(b_node.has_value());

    std::unordered_set<object_cache_key> excluded_mid{object_cache_key{b_node}};
    object_set_ref exclude_mid{excluded_mid};
    // Attempt to traverse into excluded node
    std::vector<std::variant<std::string, int64_t>> path_to_elem{"a", "b", 1};
    auto none2 = root.find_key_path(path_to_elem, exclude_mid);
    EXPECT_FALSE(none2.has_value());
}

TEST(TestObjectView, FindKeyPathVariantNegativeIndex)
{
    {
        auto root = object_builder_da::map({{"arr", object_builder_da::array({"x", "y", "z"})}});
        object_view view(root);

        std::vector<std::variant<std::string, int64_t>> key_path{"arr", -1};
        auto child = view.find_key_path(key_path);
        EXPECT_TRUE(child.is_string());
        EXPECT_STR(child.as<std::string_view>(), "z");
    }

    {
        auto root = object_builder_da::array({"x", "y", "z"});
        object_view view(root);

        std::vector<std::variant<std::string, int64_t>> key_path{-1};
        auto child = view.find_key_path(key_path);
        EXPECT_TRUE(child.is_string());
        EXPECT_STR(child.as<std::string_view>(), "z");
    }
}

TEST(TestObjectView, FindKeyPathVariantNegativeIndexOutOfBounds)
{
    {
        auto root = object_builder_da::map({{"arr", object_builder_da::array({"x", "y", "z"})}});
        object_view view(root);

        std::vector<std::variant<std::string, int64_t>> key_path{"arr", -4};
        auto child = view.find_key_path(key_path);
        EXPECT_FALSE(child.has_value());
    }

    {
        auto root = object_builder_da::array({"x", "y", "z"});
        object_view view(root);

        std::vector<std::variant<std::string, int64_t>> key_path{-4};
        auto child = view.find_key_path(key_path);
        EXPECT_FALSE(child.has_value());
    }
}

TEST(TestObjectView, FindKeyPathVariantNegativeIndexWithExclusion)
{
    {
        auto root = object_builder_da::map({{"arr", object_builder_da::array({"x", "y", "z"})}});
        object_view view(root);

        std::unordered_set<object_cache_key> excluded;
        object_set_ref exclude{excluded};

        std::vector<std::variant<std::string, int64_t>> key_path{"arr", -2};
        auto child = view.find_key_path(key_path, exclude);
        EXPECT_TRUE(child.is_string());
        EXPECT_STR(child.as<std::string_view>(), "y");
    }

    {
        auto root = object_builder_da::array({"x", "y", "z"});
        object_view view(root);

        std::unordered_set<object_cache_key> excluded;
        object_set_ref exclude{excluded};

        std::vector<std::variant<std::string, int64_t>> key_path{-2};
        auto child = view.find_key_path(key_path, exclude);
        EXPECT_TRUE(child.is_string());
        EXPECT_STR(child.as<std::string_view>(), "y");
    }
}

TEST(TestObjectView, FindKeyPathVariantPositiveIndex)
{
    {
        auto root = object_builder_da::map({{"arr", object_builder_da::array({"x", "y", "z"})}});
        object_view view(root);

        std::vector<std::variant<std::string, int64_t>> key_path{"arr", 1};
        auto child = view.find_key_path(key_path);
        EXPECT_TRUE(child.is_string());
        EXPECT_STR(child.as<std::string_view>(), "y");
    }

    {
        auto root = object_builder_da::array({"x", "y", "z"});
        object_view view(root);

        std::vector<std::variant<std::string, int64_t>> key_path{1};
        auto child = view.find_key_path(key_path);
        EXPECT_TRUE(child.is_string());
        EXPECT_STR(child.as<std::string_view>(), "y");
    }
}

TEST(TestObjectView, FindKeyPathVariantPositiveIndexOutOfBounds)
{
    {
        auto root = object_builder_da::map({{"arr", object_builder_da::array({"x", "y", "z"})}});
        object_view view(root);

        std::vector<std::variant<std::string, int64_t>> key_path{"arr", 3};
        auto child = view.find_key_path(key_path);
        EXPECT_FALSE(child.has_value());
    }
    {
        auto root = object_builder_da::array({"x", "y", "z"});
        object_view view(root);

        std::vector<std::variant<std::string, int64_t>> key_path{3};
        auto child = view.find_key_path(key_path);
        EXPECT_FALSE(child.has_value());
    }
}

TEST(TestObjectView, FindKeyPathVariantPositiveIndexWithExclusion)
{
    {
        auto root = object_builder_da::map({{"arr", object_builder_da::array({"x", "y", "z"})}});
        object_view view(root);

        std::unordered_set<object_cache_key> excluded;
        object_set_ref exclude{excluded};

        std::vector<std::variant<std::string, int64_t>> key_path{"arr", 0};
        auto child = view.find_key_path(key_path, exclude);
        EXPECT_TRUE(child.is_string());
        EXPECT_STR(child.as<std::string_view>(), "x");
    }

    {
        auto root = object_builder_da::array({"x", "y", "z"});
        object_view view(root);

        std::unordered_set<object_cache_key> excluded;
        object_set_ref exclude{excluded};

        std::vector<std::variant<std::string, int64_t>> key_path{0};
        auto child = view.find_key_path(key_path, exclude);
        EXPECT_TRUE(child.is_string());
        EXPECT_STR(child.as<std::string_view>(), "x");
    }
}

TEST(TestObjectView, CloneInvalid)
{
    owned_object input_data = owned_object{};
    object_view input{input_data};
    auto output = input.clone(memory::get_default_resource());
    EXPECT_TRUE(output.is_invalid());
}

TEST(TestObjectView, CloneNull)
{
    auto input_data = owned_object::make_null();
    object_view input{input_data};

    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::null);
}

TEST(TestObjectView, CloneBool)
{
    auto input_data = owned_object::make_boolean(true);
    object_view input{input_data};

    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::boolean);
    EXPECT_EQ(output.as<bool>(), true);
}

TEST(TestObjectView, CloneSigned)
{
    auto input_data = owned_object::make_signed(-5);
    object_view input{input_data};

    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::int64);
    EXPECT_EQ(output.as<int64_t>(), -5);
}

TEST(TestObjectView, CloneUnsigned)
{
    auto input_data = owned_object::make_unsigned(5);
    object_view input{input_data};

    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::uint64);
    EXPECT_EQ(output.as<uint64_t>(), 5);
}

TEST(TestObjectView, CloneFloat)
{
    auto input_data = owned_object::make_float(5.1);
    object_view input{input_data};

    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::float64);
    EXPECT_EQ(output.as<double>(), 5.1);
}

TEST(TestObjectView, CloneString)
{
    auto input_data = test::ddwaf_object_da::make_string("this is a string");
    object_view input{input_data};

    auto output = input.clone(memory::get_default_resource());
    EXPECT_TRUE(output.is_string());
    EXPECT_EQ(input.as<std::string_view>(), output.as<std::string_view>());
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObjectView, CloneEmptyArray)
{
    auto input_data = test::ddwaf_object_da::make_array();
    object_view input{input_data};

    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::array);
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObjectView, CloneEmptyMap)
{
    auto input_data = test::ddwaf_object_da::make_map();
    object_view input{input_data};

    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObjectView, CloneArray)
{
    auto input_data = test::ddwaf_object_da::make_array();
    input_data.emplace_back(owned_object::make_boolean(true));
    input_data.emplace_back(test::ddwaf_object_da::make_string("string"));
    input_data.emplace_back(owned_object::make_signed(5));
    object_view input{input_data};

    auto output_data = input.clone(memory::get_default_resource());
    object_view output{output_data};

    EXPECT_EQ(output.type(), object_type::array);
    EXPECT_EQ(input.size(), output.size());

    {
        auto [input_key, input_child] = input.at(0);
        auto [output_key, output_child] = output.at(0);

        EXPECT_FALSE(output_key.has_value());
        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
    }

    {
        auto [input_key, input_child] = input.at(1);
        auto [output_key, output_child] = output.at(1);

        EXPECT_FALSE(output_key.has_value());
        EXPECT_EQ(output_child.type(), input_child.type());

        auto output_str = output_child.as<std::string_view>();
        auto input_str = input_child.as<std::string_view>();
        EXPECT_EQ(output_str, input_str);
        EXPECT_NE(output_str.data(), input_str.data());
    }

    {
        auto [input_key, input_child] = input.at(2);
        auto [output_key, output_child] = output.at(2);

        EXPECT_FALSE(output_key.has_value());
        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
    }
}

TEST(TestObjectView, CloneMap)
{
    owned_object input_data = test::ddwaf_object_da::make_map();
    input_data.emplace("bool", owned_object::make_boolean(true));
    input_data.emplace("string", test::ddwaf_object_da::make_string("string"));
    input_data.emplace("signed", owned_object::make_signed(5));
    object_view input{input_data};

    auto output_data = input.clone(memory::get_default_resource());
    object_view output{output_data};

    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());

    {
        auto [input_key, input_child] = input.at(0);
        auto [output_key, output_child] = output.at(0);

        EXPECT_EQ(input_key.as<std::string_view>(), output_key.as<std::string_view>());
        EXPECT_NE(input_key.data(), output_key.data());
        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
    }

    {
        auto [input_key, input_child] = input.at(1);
        auto [output_key, output_child] = output.at(1);

        EXPECT_EQ(input_key.as<std::string_view>(), output_key.as<std::string_view>());
        EXPECT_NE(input_key.data(), output_key.data());

        EXPECT_EQ(output_child.type(), input_child.type());

        auto output_str = output_child.as<std::string_view>();
        auto input_str = input_child.as<std::string_view>();
        EXPECT_EQ(output_str, input_str);
        EXPECT_NE(output_str.data(), input_str.data());
    }

    {
        auto [input_key, input_child] = input.at(2);
        auto [output_key, output_child] = output.at(2);

        EXPECT_EQ(input_key.as<std::string_view>(), output_key.as<std::string_view>());
        EXPECT_NE(input_key.data(), output_key.data());

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
    }
}

TEST(TestArrayView, InvalidArray)
{
    auto root = test::ddwaf_object_da::make_map();
    EXPECT_THROW(array_view view{root}, std::invalid_argument);
    EXPECT_THROW(array_view view{nullptr}, std::invalid_argument);
}

TEST(TestArrayView, Default)
{
    array_view view;
    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    for (auto value : view) { EXPECT_FALSE(value.has_value()); }
}

TEST(TestArrayView, AtAccess)
{
    auto root = test::ddwaf_object_da::make_array();
    for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i + 100)); }

    array_view view(root);
    EXPECT_EQ(view.size(), 20);
    EXPECT_FALSE(view.empty());

    for (unsigned i = 0; i < 20; i++) {
        auto expected_value = std::to_string(100 + i);
        auto value = view.at(i);
        EXPECT_EQ(value.as<std::string>(), expected_value);
    }
}

TEST(TestArrayView, IteratorAccess)
{
    auto root = test::ddwaf_object_da::make_array();
    for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i + 100)); }

    array_view view(root);
    EXPECT_EQ(view.size(), 20);
    EXPECT_FALSE(view.empty());

    unsigned i = 0;
    for (auto value : view) {
        auto expected_value = std::to_string(100 + i++);
        EXPECT_EQ(value.as<std::string>(), expected_value);
    }
}

TEST(TestMapView, InvalidMap)
{
    auto root = test::ddwaf_object_da::make_array();
    EXPECT_THROW(map_view view{root}, std::invalid_argument);
    EXPECT_THROW(map_view view{nullptr}, std::invalid_argument);
}

TEST(TestMapView, Default)
{
    map_view view;
    EXPECT_EQ(view.size(), 0);
    EXPECT_TRUE(view.empty());

    for (auto [key, value] : view) {
        EXPECT_FALSE(key.has_value());
        EXPECT_FALSE(value.has_value());
    }
}

TEST(TestMapView, AtAccess)
{
    auto root = test::ddwaf_object_da::make_map();
    for (unsigned i = 0; i < 20; i++) { root.emplace(std::to_string(i), std::to_string(i + 100)); }

    map_view view(root);
    EXPECT_EQ(view.size(), 20);
    EXPECT_FALSE(view.empty());

    for (unsigned i = 0; i < 20; i++) {
        auto expected_key = std::to_string(i);
        auto expected_value = std::to_string(100 + i);
        {
            auto [key, value] = view.at(i);
            EXPECT_EQ(key.as<std::string_view>(), expected_key);
            EXPECT_EQ(value.as<std::string_view>(), expected_value);
        }

        {
            auto value = view.at_value(i);
            EXPECT_EQ(value.as<std::string>(), expected_value);
        }

        {
            auto key = view.at_key(i);
            EXPECT_EQ(key.as<std::string_view>(), expected_key);
        }
    }
}

TEST(TestMapView, FindAccess)
{
    auto root = test::ddwaf_object_da::make_map();
    for (unsigned i = 0; i < 20; i++) { root.emplace(std::to_string(i), std::to_string(i + 100)); }

    map_view view(root);
    EXPECT_EQ(view.size(), 20);
    EXPECT_FALSE(view.empty());

    for (unsigned i = 0; i < 20; i++) {
        auto expected_key = std::to_string(i);
        auto expected_value = std::to_string(100 + i);

        auto value = view.find(expected_key);
        EXPECT_EQ(value.as<std::string_view>(), expected_value);
    }

    {
        auto value = view.find("random");
        EXPECT_FALSE(value.has_value());
    }
}

TEST(TestMapView, IteratorAccess)
{
    auto root = test::ddwaf_object_da::make_map();
    for (unsigned i = 0; i < 20; i++) { root.emplace(std::to_string(i), std::to_string(i + 100)); }

    map_view view(root);
    EXPECT_EQ(view.size(), 20);
    EXPECT_FALSE(view.empty());

    unsigned i = 0;
    for (auto [key, value] : view) {
        auto expected_key = std::to_string(i);
        auto expected_value = std::to_string(100 + i);
        ++i;

        {
            EXPECT_EQ(key.as<std::string_view>(), expected_key);
            EXPECT_EQ(value.as<std::string_view>(), expected_value);
        }
    }
}

} // namespace
