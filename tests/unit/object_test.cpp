// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/gtest_utils.hpp"
#include "memory_resource.hpp"
#include "object.hpp"

#include <stdexcept>

using namespace ddwaf;
using namespace std::literals;

namespace {

class counting_resource : public memory::memory_resource {
public:
    [[nodiscard]] std::size_t allocations() const { return allocations_; }
    [[nodiscard]] std::size_t deallocations() const { return deallocations_; }

private:
    void *do_allocate(std::size_t bytes, std::size_t alignment) override
    {
        ++allocations_;
        return resource_->allocate(bytes, alignment);
    }

    void do_deallocate(void *ptr, std::size_t bytes, std::size_t alignment) override
    {
        ++deallocations_;
        resource_->deallocate(ptr, bytes, alignment);
    }

    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override
    {
        return &other == resource_;
    }

    std::size_t allocations_{0};
    std::size_t deallocations_{0};
    memory::memory_resource *resource_{memory::get_default_resource()};
};

class null_counting_resource : public memory::memory_resource {
public:
    [[nodiscard]] std::size_t deallocations() const { return deallocations_; }

private:
    void *do_allocate(std::size_t /*bytes*/, std::size_t /*alignment*/) override
    {
        throw std::bad_alloc();
    }

    void do_deallocate(void * /*ptr*/, std::size_t /*bytes*/, std::size_t /*alignment*/) override
    {
        ++deallocations_;
    }

    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override
    {
        return &other == memory::get_default_null_resource();
    }

    std::size_t deallocations_{0};
};

TEST(TestObject, NullBorrowedObject)
{
    EXPECT_THROW(borrowed_object{nullptr}, std::invalid_argument);
}

TEST(TestObject, InvalidObject)
{
    owned_object ow;
    EXPECT_EQ(ow.type(), object_type::invalid);
    EXPECT_TRUE(ow.is_invalid());
    EXPECT_FALSE(ow.is_valid());
    EXPECT_NE(ow.ptr(), nullptr);
}

TEST(TestObject, NullObject)
{
    {
        auto ow = owned_object::make_null();
        EXPECT_EQ(ow.type(), object_type::null);
    }
}

TEST(TestObject, BooleanObject)
{
    {
        auto ow = owned_object::make_boolean(true);
        EXPECT_EQ(ow.type(), object_type::boolean);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_TRUE(ow.as<bool>());
    }

    {
        owned_object ow{true};
        EXPECT_EQ(ow.type(), object_type::boolean);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_TRUE(ow.as<bool>());
    }
}

TEST(TestObject, SignedObject)
{
    {
        auto ow = owned_object::make_signed(-20);
        EXPECT_EQ(ow.type(), object_type::int64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<int64_t>(), -20);
    }

    {
        owned_object ow{-20L};
        EXPECT_EQ(ow.type(), object_type::int64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<int64_t>(), -20);
    }
}

TEST(TestObject, UnsignedObject)
{
    {
        auto ow = owned_object::make_unsigned(20);
        EXPECT_EQ(ow.type(), object_type::uint64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<uint64_t>(), 20);
    }

    {
        owned_object ow(20UL);
        EXPECT_EQ(ow.type(), object_type::uint64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<uint64_t>(), 20);
    }
}

TEST(TestObject, FloatObject)
{
    {
        auto ow = owned_object::make_float(20.5);
        EXPECT_EQ(ow.type(), object_type::float64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<double>(), 20.5);
    }

    {
        owned_object ow{20.5};
        EXPECT_EQ(ow.type(), object_type::float64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<double>(), 20.5);
    }
}

TEST(TestObject, StringObject)
{
    {
        auto ow = owned_object::make_string("this is a string");
        EXPECT_EQ(ow.type(), object_type::string);
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
    }

    {
        owned_object ow{"this is a string"};
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
    }
}

TEST(TestObject, StringObjectWithAllocator)
{
    counting_resource alloc;

    {
        auto ow = owned_object::make_string("this is a string", &alloc);
        EXPECT_EQ(ow.type(), object_type::string);
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
    }

    EXPECT_EQ(alloc.allocations(), 1);
    EXPECT_EQ(alloc.deallocations(), 1);

    {
        owned_object ow{"this is a string", &alloc};
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
    }

    EXPECT_EQ(alloc.allocations(), 2);
    EXPECT_EQ(alloc.deallocations(), 2);
}

TEST(TestObject, SmallStringObject)
{
    {
        auto ow = owned_object::make_string("string");
        EXPECT_EQ(ow.type(), object_type::small_string);
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "string");
    }

    {
        owned_object ow{"string"};
        EXPECT_EQ(ow.type(), object_type::small_string);
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "string");
    }
}

TEST(TestObject, StringLiteralObject)
{
    auto ow = owned_object::make_string_literal(STRL("this is a string"));
    EXPECT_EQ(ow.type(), object_type::literal_string);
    EXPECT_TRUE(ow.is_string());
    EXPECT_TRUE(ow.is_valid());
    EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
}

TEST(TestObject, EmptyArrayObject)
{
    {
        auto root = owned_object::make_array();
        EXPECT_EQ(root.type(), object_type::array);
        EXPECT_TRUE(root.is_valid());
        EXPECT_TRUE(root.is_array());
        EXPECT_TRUE(root.empty());
        EXPECT_EQ(root.size(), 0);
    }

    {
        auto root = owned_object::make_array(0);
        EXPECT_EQ(root.type(), object_type::array);
        EXPECT_TRUE(root.is_valid());
        EXPECT_TRUE(root.is_array());
        EXPECT_TRUE(root.empty());
        EXPECT_EQ(root.size(), 0);
    }
}

TEST(TestObject, EmptyArrayObjectWithAllocator)
{
    counting_resource alloc;

    {
        auto root = owned_object::make_array(0, &alloc);
        EXPECT_EQ(root.type(), object_type::array);
        EXPECT_TRUE(root.is_valid());
        EXPECT_TRUE(root.is_array());
        EXPECT_TRUE(root.empty());
        EXPECT_EQ(root.size(), 0);
    }

    EXPECT_EQ(alloc.allocations(), 0);
    EXPECT_EQ(alloc.deallocations(), 0);
}

TEST(TestObject, EmptyPreallocatedArrayObject)
{
    auto root = owned_object::make_array(20);
    EXPECT_EQ(root.type(), object_type::array);
    EXPECT_TRUE(root.is_valid());
    EXPECT_TRUE(root.is_array());
    EXPECT_TRUE(root.empty());
    EXPECT_EQ(root.size(), 0);
}

TEST(TestObject, EmptyPreallocatedArrayObjectWithAllocator)
{
    counting_resource alloc;

    {
        auto root = owned_object::make_array(20, &alloc);
        EXPECT_EQ(root.type(), object_type::array);
        EXPECT_TRUE(root.is_valid());
        EXPECT_TRUE(root.is_array());
        EXPECT_TRUE(root.empty());
        EXPECT_EQ(root.size(), 0);
    }

    EXPECT_EQ(alloc.allocations(), 1);
    EXPECT_EQ(alloc.deallocations(), 1);
}

TEST(TestObject, ArrayObjectEmplaceBack)
{
    auto root = owned_object::make_array();
    EXPECT_EQ(root.type(), object_type::array);
    EXPECT_TRUE(root.is_valid());

    for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i + 100)); }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::array);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_TRUE(view.is_array());

    EXPECT_EQ(view.ptr(), root.ptr());

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

TEST(TestObject, ArrayObjectEmplaceBackWithAllocator)
{
    counting_resource alloc;

    {
        auto root = owned_object::make_array(0, &alloc);
        EXPECT_EQ(root.type(), object_type::array);
        EXPECT_TRUE(root.is_valid());

        for (unsigned i = 0; i < 20; i++) {
            root.emplace_back(
                owned_object::make_string(std::to_string(i) + "_012345678901234"s, &alloc));
        }

        object_view view(root);
        ASSERT_TRUE(view.has_value());
        EXPECT_EQ(view.size(), 20);
        EXPECT_EQ(view.type(), object_type::array);
        EXPECT_TRUE(view.is_container());
        EXPECT_FALSE(view.is_scalar());
        EXPECT_FALSE(view.is_map());
        EXPECT_TRUE(view.is_array());

        EXPECT_EQ(view.ptr(), root.ptr());

        for (unsigned i = 0; i < 20; i++) {
            auto expected_value = std::to_string(i) + "_012345678901234";

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

    EXPECT_EQ(alloc.allocations(), 23);
    EXPECT_EQ(alloc.deallocations(), 23);
}

TEST(TestObject, PreallocatedArrayObjectEmplaceBack)
{
    auto root = owned_object::make_array(20);
    EXPECT_EQ(root.type(), object_type::array);
    EXPECT_TRUE(root.is_valid());

    for (unsigned i = 0; i < 20; i++) { root.emplace_back(std::to_string(i + 100)); }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::array);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_FALSE(view.is_map());
    EXPECT_TRUE(view.is_array());

    EXPECT_EQ(view.ptr(), root.ptr());

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

TEST(TestObject, PreallocatedArrayObjectEmplaceBackWithAllocator)
{
    counting_resource alloc;

    {
        auto root = owned_object::make_array(20, &alloc);
        EXPECT_EQ(root.type(), object_type::array);
        EXPECT_TRUE(root.is_valid());

        for (unsigned i = 0; i < 20; i++) {
            root.emplace_back(
                owned_object::make_string(std::to_string(i) + "_012345678901234"s, &alloc));
        }

        object_view view(root);
        ASSERT_TRUE(view.has_value());
        EXPECT_EQ(view.size(), 20);
        EXPECT_EQ(view.type(), object_type::array);
        EXPECT_TRUE(view.is_container());
        EXPECT_FALSE(view.is_scalar());
        EXPECT_FALSE(view.is_map());
        EXPECT_TRUE(view.is_array());

        EXPECT_EQ(view.ptr(), root.ptr());

        for (unsigned i = 0; i < 20; i++) {
            auto expected_value = std::to_string(i) + "_012345678901234";

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

    EXPECT_EQ(alloc.allocations(), 21);
    EXPECT_EQ(alloc.deallocations(), 21);
}

TEST(TestObject, ArrayObjectIncompatibleAllocators)
{
    memory::monotonic_buffer_resource alloc;

    auto root = owned_object::make_array(20);
    EXPECT_THROW(root.emplace_back(owned_object::make_string("012345678901234"sv, &alloc)),
        std::runtime_error);
}

TEST(TestObject, EmptyMapObject)
{
    auto root = owned_object::make_map(0);
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());
    EXPECT_TRUE(root.empty());
}

TEST(TestObject, EmptyMapObjectWithAllocator)
{
    counting_resource alloc;

    {
        auto root = owned_object::make_map(0, &alloc);
        EXPECT_EQ(root.type(), object_type::map);
        EXPECT_TRUE(root.is_valid());
        EXPECT_TRUE(root.empty());
    }

    EXPECT_EQ(alloc.allocations(), 0);
    EXPECT_EQ(alloc.deallocations(), 0);
}

TEST(TestObject, EmptyPreallocatedMapObject)
{
    auto root = owned_object::make_map(20);
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());
    EXPECT_TRUE(root.empty());
}

TEST(TestObject, EmptyPreallocatedMapObjectWithAllocator)
{
    counting_resource alloc;

    {
        auto root = owned_object::make_map(20, &alloc);
        EXPECT_EQ(root.type(), object_type::map);
        EXPECT_TRUE(root.is_valid());
        EXPECT_TRUE(root.empty());
    }

    EXPECT_EQ(alloc.allocations(), 1);
    EXPECT_EQ(alloc.deallocations(), 1);
}

TEST(TestObject, MapObjectEmplace)
{
    auto root = owned_object::make_map();
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());

    for (unsigned i = 0; i < 20; i++) { root.emplace(std::to_string(i), std::to_string(i + 100)); }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::map);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_TRUE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_EQ(view.ptr(), root.ptr());

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

TEST(TestObject, MapObjectEmplaceWithAllocator)
{
    counting_resource alloc;

    {
        auto root = owned_object::make_map(0, &alloc);
        EXPECT_EQ(root.type(), object_type::map);
        EXPECT_TRUE(root.is_valid());

        for (unsigned i = 0; i < 20; i++) {
            root.emplace(std::to_string(i),
                owned_object::make_string(std::to_string(i) + "_012345678901234"s, &alloc));
        }

        object_view view(root);
        ASSERT_TRUE(view.has_value());
        EXPECT_EQ(view.size(), 20);
        EXPECT_EQ(view.type(), object_type::map);
        EXPECT_TRUE(view.is_container());
        EXPECT_FALSE(view.is_scalar());
        EXPECT_TRUE(view.is_map());
        EXPECT_FALSE(view.is_array());

        EXPECT_EQ(view.ptr(), root.ptr());

        for (unsigned i = 0; i < 20; i++) {
            auto expected_key = std::to_string(i);
            auto expected_value = std::to_string(i) + "_012345678901234"s;

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

    EXPECT_EQ(alloc.allocations(), 23);
    EXPECT_EQ(alloc.deallocations(), 23);
}

TEST(TestObject, PreallocatedMapObjectEmplace)
{
    auto root = owned_object::make_map(20);
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());

    for (unsigned i = 0; i < 20; i++) { root.emplace(std::to_string(i), std::to_string(i + 100)); }

    object_view view(root);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view.size(), 20);
    EXPECT_EQ(view.type(), object_type::map);
    EXPECT_TRUE(view.is_container());
    EXPECT_FALSE(view.is_scalar());
    EXPECT_TRUE(view.is_map());
    EXPECT_FALSE(view.is_array());

    EXPECT_EQ(view.ptr(), root.ptr());

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

TEST(TestObject, PreallocatedMapObjectEmplaceWithAllocator)
{
    counting_resource alloc;

    {
        auto root = owned_object::make_map(20, &alloc);
        EXPECT_EQ(root.type(), object_type::map);
        EXPECT_TRUE(root.is_valid());

        for (unsigned i = 0; i < 20; i++) {
            root.emplace(std::to_string(i),
                owned_object::make_string(std::to_string(i) + "_012345678901234"s, &alloc));
        }

        object_view view(root);
        ASSERT_TRUE(view.has_value());
        EXPECT_EQ(view.size(), 20);
        EXPECT_EQ(view.type(), object_type::map);
        EXPECT_TRUE(view.is_container());
        EXPECT_FALSE(view.is_scalar());
        EXPECT_TRUE(view.is_map());
        EXPECT_FALSE(view.is_array());

        EXPECT_EQ(view.ptr(), root.ptr());

        for (unsigned i = 0; i < 20; i++) {
            auto expected_key = std::to_string(i);
            auto expected_value = std::to_string(i) + "_012345678901234"s;

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

    EXPECT_EQ(alloc.allocations(), 21);
    EXPECT_EQ(alloc.deallocations(), 21);
}

TEST(TestObject, MapObjectIncompatibleAllocators)
{
    memory::monotonic_buffer_resource alloc;

    auto root = owned_object::make_map(20);
    EXPECT_THROW(root.emplace("key"sv, owned_object::make_string("012345678901234"sv, &alloc)),
        std::runtime_error);
}

TEST(TestObject, ArrayObjectBuilder)
{
    auto root = object_builder::array({"hello", "this", "is", "an", "array"});
    EXPECT_EQ(root.type(), object_type::array);
    EXPECT_TRUE(root.is_valid());
    EXPECT_EQ(root.size(), 5);
}

TEST(TestObject, MapObjectBuilder)
{
    auto root = object_builder::map({{"hello"sv, object_builder::array({"array", "value"})},
        {"this"sv, "is"sv}, {"an"sv, "array"sv}});
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());
    EXPECT_EQ(root.size(), 3);
}

TEST(TestObject, HeterogenousArrayObjectBuilder)
{
    auto root = object_builder::array({object_builder::array({"array", "value"}),
        object_builder::map({{"map", "value"}}), "small"sv, "this is a normal string view"sv,
        "this is a normal string"s, "this is a normal const char *", false,
        static_cast<int16_t>(-16), static_cast<uint16_t>(16), static_cast<int32_t>(-32),
        static_cast<uint32_t>(32), static_cast<int64_t>(-64), static_cast<uint64_t>(64), 64.64});
    EXPECT_EQ(root.type(), object_type::array);
    EXPECT_TRUE(root.is_valid());
    EXPECT_EQ(root.size(), 14);

    EXPECT_EQ(root.at(0).type(), object_type::array);
    EXPECT_EQ(root.at(1).type(), object_type::map);
    EXPECT_EQ(root.at(2).type(), object_type::small_string);
    EXPECT_EQ(root.at(3).type(), object_type::string);
    EXPECT_EQ(root.at(4).type(), object_type::string);
    EXPECT_EQ(root.at(5).type(), object_type::string);
    EXPECT_EQ(root.at(6).type(), object_type::boolean);
    EXPECT_EQ(root.at(7).type(), object_type::int64);
    EXPECT_EQ(root.at(8).type(), object_type::uint64);
    EXPECT_EQ(root.at(9).type(), object_type::int64);
    EXPECT_EQ(root.at(10).type(), object_type::uint64);
    EXPECT_EQ(root.at(11).type(), object_type::int64);
    EXPECT_EQ(root.at(12).type(), object_type::uint64);
    EXPECT_EQ(root.at(13).type(), object_type::float64);
}

TEST(TestObject, HeterogenousMapObjectBuilder)
{
    auto root = object_builder::map({
        {"array"sv, object_builder::array({"array", "value"})},
        {"map"sv, object_builder::map({{"map", "value"}})},
        {"small string"sv, "small"sv},
        {"string view"sv, "this is a normal string view"sv},
        {"string"sv, "this is a normal string"s},
        {"const char *"sv, "this is a normal const char *"},
        {"bool"sv, false},
        {"int16"sv, static_cast<int16_t>(-16)},
        {"uint16"sv, static_cast<uint16_t>(16)},
        {"int32"sv, static_cast<int32_t>(-32)},
        {"uint32"sv, static_cast<uint32_t>(32)},
        {"int64"sv, static_cast<int64_t>(-64)},
        {"uint64"sv, static_cast<uint64_t>(64)},
        {"float"sv, 64.64},
    });
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());
    EXPECT_EQ(root.size(), 14);

    EXPECT_EQ(root.at(0).type(), object_type::array);
    EXPECT_EQ(root.at(1).type(), object_type::map);
    EXPECT_EQ(root.at(2).type(), object_type::small_string);
    EXPECT_EQ(root.at(3).type(), object_type::string);
    EXPECT_EQ(root.at(4).type(), object_type::string);
    EXPECT_EQ(root.at(5).type(), object_type::string);
    EXPECT_EQ(root.at(6).type(), object_type::boolean);
    EXPECT_EQ(root.at(7).type(), object_type::int64);
    EXPECT_EQ(root.at(8).type(), object_type::uint64);
    EXPECT_EQ(root.at(9).type(), object_type::int64);
    EXPECT_EQ(root.at(10).type(), object_type::uint64);
    EXPECT_EQ(root.at(11).type(), object_type::int64);
    EXPECT_EQ(root.at(12).type(), object_type::uint64);
    EXPECT_EQ(root.at(13).type(), object_type::float64);
}

TEST(TestObject, HeterogenousArrayObjectBuilderWithAllocator)
{
    counting_resource alloc;

    {
        auto root = object_builder::array(
            {object_builder::array({"array", "value"}, &alloc),
                object_builder::map({{"map", "value"}}, &alloc), "small"sv,
                "this is a normal string view"sv, "this is a normal string"s,
                "this is a normal const char *", false, static_cast<int16_t>(-16),
                static_cast<uint16_t>(16), static_cast<int32_t>(-32), static_cast<uint32_t>(32),
                static_cast<int64_t>(-64), static_cast<uint64_t>(64), 64.64},
            &alloc);
        EXPECT_EQ(root.type(), object_type::array);
        EXPECT_TRUE(root.is_valid());
        EXPECT_EQ(root.size(), 14);

        EXPECT_EQ(root.at(0).type(), object_type::array);
        EXPECT_EQ(root.at(1).type(), object_type::map);
        EXPECT_EQ(root.at(2).type(), object_type::small_string);
        EXPECT_EQ(root.at(3).type(), object_type::string);
        EXPECT_EQ(root.at(4).type(), object_type::string);
        EXPECT_EQ(root.at(5).type(), object_type::string);
        EXPECT_EQ(root.at(6).type(), object_type::boolean);
        EXPECT_EQ(root.at(7).type(), object_type::int64);
        EXPECT_EQ(root.at(8).type(), object_type::uint64);
        EXPECT_EQ(root.at(9).type(), object_type::int64);
        EXPECT_EQ(root.at(10).type(), object_type::uint64);
        EXPECT_EQ(root.at(11).type(), object_type::int64);
        EXPECT_EQ(root.at(12).type(), object_type::uint64);
        EXPECT_EQ(root.at(13).type(), object_type::float64);
    }

    EXPECT_EQ(alloc.allocations(), 6);
    EXPECT_EQ(alloc.deallocations(), 6);
}

TEST(TestObject, HeterogenousMapObjectBuilderWithAllocator)
{
    counting_resource alloc;

    {
        auto root = object_builder::map(
            {
                {"array"sv, object_builder::array({"array", "value"}, &alloc)},
                {"map"sv, object_builder::map({{"map", "value"}}, &alloc)},
                {"small string"sv, "is"sv},
                {"string view key"sv, "this is a normal string view"sv},
                {"standard string key"sv, "this is a normal string"s},
                {"const char *"sv, "this is a normal const char *"},
                {"bool"sv, false},
                {"int16"sv, static_cast<int16_t>(-16)},
                {"uint16"sv, static_cast<uint16_t>(16)},
                {"int32"sv, static_cast<int32_t>(-32)},
                {"uint32"sv, static_cast<uint32_t>(32)},
                {"int64"sv, static_cast<int64_t>(-64)},
                {"uint64"sv, static_cast<uint64_t>(64)},
                {"float"sv, 64.64},
            },
            &alloc);

        EXPECT_EQ(root.type(), object_type::map);
        EXPECT_TRUE(root.is_valid());
        EXPECT_EQ(root.size(), 14);

        EXPECT_EQ(root.at(0).type(), object_type::array);
        EXPECT_EQ(root.at(1).type(), object_type::map);
        EXPECT_EQ(root.at(2).type(), object_type::small_string);
        EXPECT_EQ(root.at(3).type(), object_type::string);
        EXPECT_EQ(root.at(4).type(), object_type::string);
        EXPECT_EQ(root.at(5).type(), object_type::string);
        EXPECT_EQ(root.at(6).type(), object_type::boolean);
        EXPECT_EQ(root.at(7).type(), object_type::int64);
        EXPECT_EQ(root.at(8).type(), object_type::uint64);
        EXPECT_EQ(root.at(9).type(), object_type::int64);
        EXPECT_EQ(root.at(10).type(), object_type::uint64);
        EXPECT_EQ(root.at(11).type(), object_type::int64);
        EXPECT_EQ(root.at(12).type(), object_type::uint64);
        EXPECT_EQ(root.at(13).type(), object_type::float64);
    }

    EXPECT_EQ(alloc.allocations(), 8);
    EXPECT_EQ(alloc.deallocations(), 8);
}

TEST(TestObject, ArrayObjectBuilderIncompatibleAllocator)
{
    memory::monotonic_buffer_resource alloc;

    EXPECT_THROW(
        object_builder::array(
            {"hello", "this", "is", "an", "array", object_builder::array({"hello"})}, &alloc),
        std::runtime_error);
    EXPECT_THROW(object_builder::array({"hello", "this", "is", "an", "array",
                                           object_builder::map({{"hello", "bye"}})},
                     &alloc),
        std::runtime_error);

    EXPECT_THROW(object_builder::array({"hello", "this", "is", "an", "array",
                     object_builder::array({"hello"}, &alloc)}),
        std::runtime_error);
    EXPECT_THROW(object_builder::array({"hello", "this", "is", "an", "array",
                     object_builder::map({{"hello", "bye"}}, &alloc)}),
        std::runtime_error);
}

TEST(TestObject, MapObjectBuilderIncompatibleAllocators)
{
    memory::monotonic_buffer_resource alloc;
    EXPECT_THROW(object_builder::map({{"hello"sv, object_builder::array({"array", "value"})},
                                         {"this"sv, "is"sv}, {"an"sv, "array"sv}},
                     &alloc),
        std::runtime_error);
    EXPECT_THROW(object_builder::map({{"hello"sv, object_builder::map({{"array", "value"}})},
                                         {"this"sv, "is"sv}, {"an"sv, "array"sv}},
                     &alloc),
        std::runtime_error);

    EXPECT_THROW(
        object_builder::map({{"hello"sv, object_builder::array({"array", "value"}, &alloc)},
            {"this"sv, "is"sv}, {"an"sv, "array"sv}}),
        std::runtime_error);
    EXPECT_THROW(
        object_builder::map({{"hello"sv, object_builder::map({{"array", "value"}}, &alloc)},
            {"this"sv, "is"sv}, {"an"sv, "array"sv}}),
        std::runtime_error);
}

// TODO Reevaluate once allocators are exposed through the interface
/*TEST(TestObject, ObjectWithNullAllocator)*/
/*{*/
/*auto root = object_builder::map({*/
/*{"array"sv, object_builder::array({"array", "value"})},*/
/*{"map"sv, object_builder::map({{"map", "value"}})},*/
/*{"small string"sv, "small"sv},*/
/*{"string view"sv, "this is a normal string view"sv},*/
/*{"string"sv, "this is a normal string"s},*/
/*{"const char *"sv, "this is a normal const char *"},*/
/*{"bool"sv, false},*/
/*{"int16"sv, static_cast<int16_t>(-16)},*/
/*{"uint16"sv, static_cast<uint16_t>(16)},*/
/*{"int32"sv, static_cast<int32_t>(-32)},*/
/*{"uint32"sv, static_cast<uint32_t>(32)},*/
/*{"int64"sv, static_cast<int64_t>(-64)},*/
/*{"uint64"sv, static_cast<uint64_t>(64)},*/
/*{"float"sv, 64.64},*/
/*});*/

/*// Create a new owned_object using the internal reference to ensure it's not*/
/*// double freed*/
/*{*/
/*null_counting_resource alloc;*/
/*{*/
/*owned_object other{root.ref(), &alloc};*/
/*}*/
/*EXPECT_EQ(alloc.deallocations(), 0);*/
/*}*/
/*}*/

TEST(TestObject, CloneInvalid)
{
    owned_object input;
    auto output = input.clone();
    EXPECT_TRUE(output.is_invalid());
}

TEST(TestObject, CloneNull)
{
    auto input = owned_object::make_null();

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::null);
}

TEST(TestObject, CloneBool)
{
    auto input = owned_object::make_boolean(true);

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::boolean);
    EXPECT_EQ(output.as<bool>(), true);
}

TEST(TestObject, CloneSigned)
{
    auto input = owned_object::make_signed(-5);
    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::int64);
    EXPECT_EQ(output.as<int64_t>(), -5);
}

TEST(TestObject, CloneUnsigned)
{
    auto input = owned_object::make_unsigned(5);
    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::uint64);
    EXPECT_EQ(output.as<uint64_t>(), 5);
}

TEST(TestObject, CloneFloat)
{
    auto input = owned_object::make_float(5.1);
    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::float64);
    EXPECT_EQ(output.as<double>(), 5.1);
}

TEST(TestObject, CloneString)
{
    auto input = owned_object::make_string("this is a string");
    auto output = input.clone();
    EXPECT_TRUE(output.is_string());
    EXPECT_EQ(input.as<std::string_view>(), output.as<std::string_view>());
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneSmallString)
{
    auto input = owned_object::make_string("this");
    auto output = input.clone();
    EXPECT_TRUE(output.is_string());
    EXPECT_EQ(input.as<std::string_view>(), output.as<std::string_view>());
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneStringLiteral)
{
    auto input = owned_object::make_string_literal(STRL("this"));
    auto output = input.clone();
    EXPECT_TRUE(output.is_string());
    EXPECT_EQ(input.as<std::string_view>(), output.as<std::string_view>());
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneEmptyArray)
{
    auto input = owned_object::make_array();
    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::array);
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneEmptyMap)
{
    auto input = owned_object::make_map();
    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneArray)
{
    auto input = owned_object::make_array();
    input.emplace_back(true);
    input.emplace_back("string");
    input.emplace_back(5L);

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::array);
    EXPECT_EQ(input.size(), output.size());

    {
        auto input_child = input.at(0);
        auto output_child = output.at(0);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
    }

    {
        auto input_child = input.at(1);
        auto output_child = output.at(1);

        EXPECT_EQ(output_child.type(), input_child.type());

        auto output_str = output_child.as<std::string_view>();
        auto input_str = input_child.as<std::string_view>();
        EXPECT_EQ(output_str, input_str);
        EXPECT_NE(output_str.data(), input_str.data());
    }

    {
        auto input_child = input.at(2);
        auto output_child = output.at(2);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
    }
}

TEST(TestObject, CloneMap)
{
    auto input = object_builder::map({{"bool", true}, {"string", "string"}, {"signed", 5}});

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());

    {
        auto input_child = input.at(0);
        auto output_child = output.at(0);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
    }

    {
        auto input_child = input.at(1);
        auto output_child = output.at(1);

        EXPECT_EQ(output_child.type(), input_child.type());

        auto output_str = output_child.as<std::string_view>();
        auto input_str = input_child.as<std::string_view>();
        EXPECT_EQ(output_str, input_str);
        EXPECT_NE(output_str.data(), input_str.data());
    }

    {
        auto input_child = input.at(2);
        auto output_child = output.at(2);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
    }
}

TEST(TestObject, CloneHeterogenous)
{
    auto input = object_builder::map({{"bool", true}, {"string", "string"}, {"signed", 5},
        {"array", object_builder::array({"1", 2, "3", 4})}});

    auto output = input.clone();
    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());

    {
        auto input_child = input.at(0);
        auto output_child = output.at(0);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
    }

    {
        auto input_child = input.at(1);
        auto output_child = output.at(1);

        EXPECT_EQ(output_child.type(), input_child.type());

        auto output_str = output_child.as<std::string_view>();
        auto input_str = input_child.as<std::string_view>();
        EXPECT_EQ(output_str, input_str);
        EXPECT_NE(output_str.data(), input_str.data());
    }

    {
        auto input_child = input.at(2);
        auto output_child = output.at(2);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
    }

    {
        auto input_child = input.at(3);
        auto output_child = output.at(3);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.size(), input_child.size());

        {
            auto input_grandchild = input_child.at(0);
            auto output_grandchild = output_child.at(0);

            EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
            EXPECT_STR(
                output_grandchild.as<std::string_view>(), input_grandchild.as<std::string_view>());
        }

        {
            auto input_grandchild = input_child.at(1);
            auto output_grandchild = output_child.at(1);

            EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
            EXPECT_EQ(output_grandchild.as<int64_t>(), input_grandchild.as<int64_t>());
        }

        {
            auto input_grandchild = input_child.at(2);
            auto output_grandchild = output_child.at(2);

            EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
            EXPECT_STR(
                output_grandchild.as<std::string_view>(), input_grandchild.as<std::string_view>());
        }

        {
            auto input_grandchild = input_child.at(3);
            auto output_grandchild = output_child.at(3);

            EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
            EXPECT_EQ(output_grandchild.as<int64_t>(), input_grandchild.as<int64_t>());
        }
    }
}

TEST(TestObject, CloneHeterogenousWithAllocator)
{
    auto input = object_builder::map(
        {{"bool value key ...", true}, {"string value key", "string value value"},
            {"signed value key", 5}, {"array value key", object_builder::array({"1", 2, "3", 4})}});

    counting_resource alloc;

    {
        auto output = input.clone(&alloc);
        EXPECT_EQ(output.type(), object_type::map);
        EXPECT_EQ(input.size(), output.size());

        {
            auto input_child = input.at(0);
            auto output_child = output.at(0);

            EXPECT_EQ(output_child.type(), input_child.type());
            EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
        }

        {
            auto input_child = input.at(1);
            auto output_child = output.at(1);

            EXPECT_EQ(output_child.type(), input_child.type());

            auto output_str = output_child.as<std::string_view>();
            auto input_str = input_child.as<std::string_view>();
            EXPECT_EQ(output_str, input_str);
            EXPECT_NE(output_str.data(), input_str.data());
        }

        {
            auto input_child = input.at(2);
            auto output_child = output.at(2);

            EXPECT_EQ(output_child.type(), input_child.type());
            EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
        }

        {
            auto input_child = input.at(3);
            auto output_child = output.at(3);

            EXPECT_EQ(output_child.type(), input_child.type());
            EXPECT_EQ(output_child.size(), input_child.size());

            {
                auto input_grandchild = input_child.at(0);
                auto output_grandchild = output_child.at(0);

                EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
                EXPECT_STR(output_grandchild.as<std::string_view>(),
                    input_grandchild.as<std::string_view>());
            }

            {
                auto input_grandchild = input_child.at(1);
                auto output_grandchild = output_child.at(1);

                EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
                EXPECT_EQ(output_grandchild.as<int64_t>(), input_grandchild.as<int64_t>());
            }

            {
                auto input_grandchild = input_child.at(2);
                auto output_grandchild = output_child.at(2);

                EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
                EXPECT_STR(output_grandchild.as<std::string_view>(),
                    input_grandchild.as<std::string_view>());
            }

            {
                auto input_grandchild = input_child.at(3);
                auto output_grandchild = output_child.at(3);

                EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
                EXPECT_EQ(output_grandchild.as<int64_t>(), input_grandchild.as<int64_t>());
            }
        }
    }

    EXPECT_EQ(alloc.allocations(), 7);
    EXPECT_EQ(alloc.deallocations(), 7);
}

TEST(TestObject, CloneHeterogenousWithIncompatibleAllocator)
{
    auto input = object_builder::map(
        {{"bool value key ...", true}, {"string value key", "string value value"},
            {"signed value key", 5}, {"array value key", object_builder::array({"1", 2, "3", 4})}});

    memory::monotonic_buffer_resource alloc;

    auto output = input.clone(&alloc);
    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());

    {
        auto input_child = input.at(0);
        auto output_child = output.at(0);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<bool>(), input_child.as<bool>());
    }

    {
        auto input_child = input.at(1);
        auto output_child = output.at(1);

        EXPECT_EQ(output_child.type(), input_child.type());

        auto output_str = output_child.as<std::string_view>();
        auto input_str = input_child.as<std::string_view>();
        EXPECT_EQ(output_str, input_str);
        EXPECT_NE(output_str.data(), input_str.data());
    }

    {
        auto input_child = input.at(2);
        auto output_child = output.at(2);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.as<int64_t>(), input_child.as<int64_t>());
    }

    {
        auto input_child = input.at(3);
        auto output_child = output.at(3);

        EXPECT_EQ(output_child.type(), input_child.type());
        EXPECT_EQ(output_child.size(), input_child.size());

        {
            auto input_grandchild = input_child.at(0);
            auto output_grandchild = output_child.at(0);

            EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
            EXPECT_STR(
                output_grandchild.as<std::string_view>(), input_grandchild.as<std::string_view>());
        }

        {
            auto input_grandchild = input_child.at(1);
            auto output_grandchild = output_child.at(1);

            EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
            EXPECT_EQ(output_grandchild.as<int64_t>(), input_grandchild.as<int64_t>());
        }

        {
            auto input_grandchild = input_child.at(2);
            auto output_grandchild = output_child.at(2);

            EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
            EXPECT_STR(
                output_grandchild.as<std::string_view>(), input_grandchild.as<std::string_view>());
        }

        {
            auto input_grandchild = input_child.at(3);
            auto output_grandchild = output_child.at(3);

            EXPECT_EQ(output_grandchild.type(), input_grandchild.type());
            EXPECT_EQ(output_grandchild.as<int64_t>(), input_grandchild.as<int64_t>());
        }
    }
}

} // namespace
