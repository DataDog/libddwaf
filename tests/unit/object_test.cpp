// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "common/ddwaf_object_da.hpp"
#include "common/gtest_utils.hpp"
#include "memory_resource.hpp"
#include "object.hpp"

#include <cstring>
#include <limits>
#include <stdexcept>

using namespace ddwaf;

using namespace ddwaf::test;
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

class tracking_resource : public memory::memory_resource {
public:
    void fail_allocations(bool fail) { fail_allocations_ = fail; }

    [[nodiscard]] std::size_t allocations() const { return allocations_; }
    [[nodiscard]] std::size_t failed_allocations() const { return failed_allocations_; }
    [[nodiscard]] std::size_t deallocations() const { return deallocations_; }
    [[nodiscard]] std::size_t last_allocation_bytes() const { return last_allocation_bytes_; }
    [[nodiscard]] std::size_t last_allocation_alignment() const
    {
        return last_allocation_alignment_;
    }
    [[nodiscard]] std::size_t last_deallocation_bytes() const { return last_deallocation_bytes_; }
    [[nodiscard]] std::size_t last_deallocation_alignment() const
    {
        return last_deallocation_alignment_;
    }

private:
    void *do_allocate(std::size_t bytes, std::size_t alignment) override
    {
        if (fail_allocations_) {
            ++failed_allocations_;
            throw std::bad_alloc();
        }
        ++allocations_;
        last_allocation_bytes_ = bytes;
        last_allocation_alignment_ = alignment;
        return resource_->allocate(bytes, alignment);
    }

    void do_deallocate(void *ptr, std::size_t bytes, std::size_t alignment) override
    {
        ++deallocations_;
        last_deallocation_bytes_ = bytes;
        last_deallocation_alignment_ = alignment;
        resource_->deallocate(ptr, bytes, alignment);
    }

    [[nodiscard]] bool do_is_equal(const std::pmr::memory_resource &other) const noexcept override
    {
        return this == &other;
    }

    bool fail_allocations_{false};
    std::size_t allocations_{0};
    std::size_t failed_allocations_{0};
    std::size_t deallocations_{0};
    std::size_t last_allocation_bytes_{0};
    std::size_t last_allocation_alignment_{0};
    std::size_t last_deallocation_bytes_{0};
    std::size_t last_deallocation_alignment_{0};
    memory::memory_resource *resource_{memory::get_default_resource()};
};

TEST(TestObject, NullBorrowedObject)
{
    EXPECT_THROW(borrowed_object(nullptr, memory::get_default_resource()), std::invalid_argument);
}

TEST(TestObject, NormalizeSignedIndex)
{
    EXPECT_EQ(detail::normalize_index(3, 0), 0);
    EXPECT_EQ(detail::normalize_index(3, 2), 2);
    EXPECT_EQ(detail::normalize_index(3, -1), 2);
    EXPECT_EQ(detail::normalize_index(3, -3), 0);
    EXPECT_FALSE(detail::normalize_index(3, 3).has_value());
    EXPECT_FALSE(detail::normalize_index(3, -4).has_value());
    EXPECT_FALSE(detail::normalize_index(3, std::numeric_limits<int64_t>::min()).has_value());

    if constexpr (sizeof(std::size_t) >= sizeof(uint64_t)) {
        constexpr auto large_size =
            static_cast<std::size_t>(std::numeric_limits<int64_t>::max()) + std::size_t{2};
        EXPECT_EQ(detail::normalize_index(large_size, std::numeric_limits<int64_t>::max()),
            static_cast<std::size_t>(std::numeric_limits<int64_t>::max()));
        EXPECT_EQ(detail::normalize_index(large_size, std::numeric_limits<int64_t>::min()), 1);
    }
}

TEST(TestObject, InvalidObject)
{
    owned_object ow = owned_object{};
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
        owned_object ow = test::ddwaf_object_da::make_boolean(true);
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
        owned_object ow = test::ddwaf_object_da::make_signed(-20L);
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
        owned_object ow = test::ddwaf_object_da::make_unsigned(20UL);
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
        owned_object ow = test::ddwaf_object_da::make_float(20.5);
        EXPECT_EQ(ow.type(), object_type::float64);
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<double>(), 20.5);
    }
}

TEST(TestObject, StringObject)
{
    {
        auto ow = test::ddwaf_object_da::make_string("this is a string");
        EXPECT_EQ(ow.type(), object_type::string);
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
    }

    {
        owned_object ow = test::ddwaf_object_da::make_string("this is a string");
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
    }
}

TEST(TestObject, StringObjectWithAllocator)
{
    counting_resource alloc;

    {
        auto ow = test::ddwaf_object_da::make_string("this is a string", &alloc);
        EXPECT_EQ(ow.type(), object_type::string);
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "this is a string");
    }

    EXPECT_EQ(alloc.allocations(), 1);
    EXPECT_EQ(alloc.deallocations(), 1);

    {
        owned_object ow = owned_object::make_string("this is a string", &alloc);
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
        auto ow = test::ddwaf_object_da::make_string("string");
        EXPECT_EQ(ow.type(), object_type::small_string);
        EXPECT_TRUE(ow.is_string());
        EXPECT_TRUE(ow.is_valid());
        EXPECT_EQ(ow.as<std::string_view>(), "string");
    }

    {
        owned_object ow = test::ddwaf_object_da::make_string("string");
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
        auto root = test::ddwaf_object_da::make_array();
        EXPECT_EQ(root.type(), object_type::array);
        EXPECT_TRUE(root.is_valid());
        EXPECT_TRUE(root.is_array());
        EXPECT_TRUE(root.empty());
        EXPECT_EQ(root.size(), 0);
    }

    {
        auto root = test::ddwaf_object_da::make_array(0);
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
        auto root = owned_object::make_array(&alloc);
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
    auto root = test::ddwaf_object_da::make_array(20);
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

TEST(TestObject, LargeArrayAllocationGrowthAndFailure)
{
    tracking_resource alloc;
    constexpr std::size_t initial_capacity = 2;
    constexpr std::size_t grown_capacity = initial_capacity * 2;

    {
        auto root = owned_object::make_large_array(initial_capacity, &alloc);
        EXPECT_EQ(root.type(), object_type::large_array);
        EXPECT_TRUE(root.is_array());
        EXPECT_EQ(root.ref().via.large_array._type, static_cast<uint8_t>(object_type::large_array));
        EXPECT_EQ(root.ref().via.large_array.size, 0);
        EXPECT_EQ(root.ref().via.large_array.capacity, initial_capacity);
        EXPECT_EQ(alloc.last_allocation_bytes(), initial_capacity * sizeof(detail::object));
        EXPECT_EQ(alloc.last_allocation_alignment(), alignof(detail::object));

        root.emplace_back(1U);
        root.emplace_back(2U);
        const auto *initial_data = root.ref().via.large_array.ptr;
        EXPECT_EQ(root.ref().via.large_array.size, initial_capacity);

        alloc.fail_allocations(true);
        EXPECT_THROW(root.emplace_back(3U), std::bad_alloc);
        EXPECT_EQ(alloc.failed_allocations(), 1);
        EXPECT_EQ(root.ref().via.large_array.ptr, initial_data);
        EXPECT_EQ(root.ref().via.large_array.size, initial_capacity);
        EXPECT_EQ(root.ref().via.large_array.capacity, initial_capacity);
        EXPECT_EQ(root.size(), initial_capacity);
        EXPECT_EQ(root.at(0).as<std::uint64_t>(), 1);
        EXPECT_EQ(root.at(1).as<std::uint64_t>(), 2);

        alloc.fail_allocations(false);
        root.emplace_back(3U);
        EXPECT_NE(root.ref().via.large_array.ptr, initial_data);
        EXPECT_EQ(root.size(), 3);
        EXPECT_EQ(root.ref().via.large_array.size, 3);
        EXPECT_EQ(root.ref().via.large_array.capacity, grown_capacity);
        EXPECT_EQ(alloc.last_allocation_bytes(), grown_capacity * sizeof(detail::object));
        EXPECT_EQ(alloc.last_deallocation_bytes(), initial_capacity * sizeof(detail::object));
        EXPECT_EQ(alloc.last_deallocation_alignment(), alignof(detail::object));
    }

    EXPECT_EQ(alloc.allocations(), 2);
    EXPECT_EQ(alloc.deallocations(), 2);
    EXPECT_EQ(alloc.last_deallocation_bytes(), grown_capacity * sizeof(detail::object));
    EXPECT_EQ(alloc.last_deallocation_alignment(), alignof(detail::object));
}

TEST(TestObject, LargeMapAllocationGrowthAndFailure)
{
    tracking_resource alloc;
    constexpr std::size_t initial_capacity = 1;
    constexpr std::size_t grown_capacity = initial_capacity * 2;

    {
        auto root = owned_object::make_large_map(initial_capacity, &alloc);
        EXPECT_EQ(root.type(), object_type::large_map);
        EXPECT_TRUE(root.is_map());
        EXPECT_EQ(root.ref().via.large_map._type, static_cast<uint8_t>(object_type::large_map));
        EXPECT_EQ(root.ref().via.large_map.size, 0);
        EXPECT_EQ(root.ref().via.large_map.capacity, initial_capacity);
        EXPECT_EQ(alloc.last_allocation_bytes(), initial_capacity * sizeof(detail::object_kv));
        EXPECT_EQ(alloc.last_allocation_alignment(), alignof(detail::object_kv));

        root.emplace("one", 1U);
        const auto *initial_data = root.ref().via.large_map.ptr;
        EXPECT_EQ(root.ref().via.large_map.size, initial_capacity);

        alloc.fail_allocations(true);
        EXPECT_THROW(root.emplace("two", 2U), std::bad_alloc);
        EXPECT_EQ(alloc.failed_allocations(), 1);
        EXPECT_EQ(root.ref().via.large_map.ptr, initial_data);
        EXPECT_EQ(root.ref().via.large_map.size, initial_capacity);
        EXPECT_EQ(root.ref().via.large_map.capacity, initial_capacity);
        EXPECT_EQ(root.size(), initial_capacity);
        EXPECT_EQ(root.at(0).as<std::uint64_t>(), 1);

        alloc.fail_allocations(false);
        root.emplace("two", 2U);
        EXPECT_NE(root.ref().via.large_map.ptr, initial_data);
        EXPECT_EQ(root.size(), 2);
        EXPECT_EQ(root.ref().via.large_map.size, 2);
        EXPECT_EQ(root.ref().via.large_map.capacity, grown_capacity);
        EXPECT_EQ(alloc.last_allocation_bytes(), grown_capacity * sizeof(detail::object_kv));
        EXPECT_EQ(alloc.last_deallocation_bytes(), initial_capacity * sizeof(detail::object_kv));
        EXPECT_EQ(alloc.last_deallocation_alignment(), alignof(detail::object_kv));
    }

    EXPECT_EQ(alloc.allocations(), 2);
    EXPECT_EQ(alloc.deallocations(), 2);
    EXPECT_EQ(alloc.last_deallocation_bytes(), grown_capacity * sizeof(detail::object_kv));
    EXPECT_EQ(alloc.last_deallocation_alignment(), alignof(detail::object_kv));
}

TEST(TestObject, LargeContainerOverflowAndExhaustedCapacity)
{
    tracking_resource alloc;
    constexpr auto array_maximum = detail::max_large_array_capacity;
    constexpr auto map_maximum = detail::max_large_map_capacity;

    static_assert(array_maximum <= detail::large_container_metadata_capacity_limit);
    static_assert(map_maximum <= detail::large_container_metadata_capacity_limit);
    EXPECT_THROW(owned_object::make_large_array(array_maximum + 1, &alloc), std::length_error);
    EXPECT_THROW(owned_object::make_large_map(map_maximum + 1, &alloc), std::length_error);
    EXPECT_THROW(detail::next_large_capacity(array_maximum, array_maximum), std::length_error);
    EXPECT_THROW(detail::next_large_capacity(map_maximum, map_maximum), std::length_error);

    auto exhausted_array = detail::make_large_array_object(nullptr, array_maximum, array_maximum);
    EXPECT_THROW(detail::grow_large_array(exhausted_array, alloc), std::length_error);
    EXPECT_EQ(exhausted_array.via.large_array.ptr, nullptr);
    EXPECT_EQ(detail::large_container_size(exhausted_array), array_maximum);
    EXPECT_EQ(detail::large_container_capacity(exhausted_array), array_maximum);

    auto exhausted_map = detail::make_large_map_object(nullptr, map_maximum, map_maximum);
    EXPECT_THROW(detail::grow_large_map(exhausted_map, alloc), std::length_error);
    EXPECT_EQ(exhausted_map.via.large_map.ptr, nullptr);
    EXPECT_EQ(detail::large_container_size(exhausted_map), map_maximum);
    EXPECT_EQ(detail::large_container_capacity(exhausted_map), map_maximum);
    EXPECT_EQ(alloc.allocations(), 0);
}

TEST(TestObject, LargeContainerRecursiveDestruction)
{
    tracking_resource alloc;
    {
        auto root = owned_object::make_large_map(1, &alloc);
        auto nested = owned_object::make_large_array(1, &alloc);
        nested.emplace_back(owned_object::make_string("an allocated nested string", &alloc));
        root.emplace("nested", std::move(nested));
        EXPECT_EQ(alloc.allocations(), 3);
    }
    EXPECT_EQ(alloc.deallocations(), 3);
}

TEST(TestObject, CompactContainerPromotionAllocation)
{
    static constexpr auto compact_capacity = std::numeric_limits<std::uint16_t>::max();
    static constexpr std::size_t promoted_capacity = compact_capacity * std::size_t{2};

    {
        tracking_resource alloc;
        auto root = owned_object::make_array(compact_capacity, &alloc);
        std::memset(root.ref().via.array.ptr, 0, compact_capacity * sizeof(detail::object));
        root.ref().via.array.size = compact_capacity;
        const auto *compact_data = root.ref().via.array.ptr;

        alloc.fail_allocations(true);
        EXPECT_THROW(root.emplace_back(42U), std::bad_alloc);
        EXPECT_EQ(root.type(), object_type::array);
        EXPECT_EQ(root.size(), compact_capacity);
        EXPECT_EQ(root.ref().via.array.ptr, compact_data);

        alloc.fail_allocations(false);
        root.emplace_back(42U);
        EXPECT_EQ(root.type(), object_type::large_array);
        EXPECT_EQ(root.size(), compact_capacity + std::size_t{1});
        EXPECT_EQ(root.ref().via.large_array._type, static_cast<uint8_t>(object_type::large_array));
        EXPECT_EQ(root.ref().via.large_array.size, compact_capacity + std::size_t{1});
        EXPECT_EQ(root.ref().via.large_array.capacity, promoted_capacity);
        EXPECT_EQ(root.at(compact_capacity).as<std::uint64_t>(), 42);
        EXPECT_EQ(alloc.last_allocation_bytes(), promoted_capacity * sizeof(detail::object));
        EXPECT_EQ(alloc.last_allocation_alignment(), alignof(detail::object));
        EXPECT_EQ(alloc.last_deallocation_bytes(), compact_capacity * sizeof(detail::object));
        EXPECT_EQ(alloc.last_deallocation_alignment(), alignof(detail::object));
    }

    {
        tracking_resource alloc;
        auto root = owned_object::make_map(compact_capacity, &alloc);
        std::memset(root.ref().via.map.ptr, 0, compact_capacity * sizeof(detail::object_kv));
        root.ref().via.map.size = compact_capacity;

        root.emplace("last", 42U);
        EXPECT_EQ(root.type(), object_type::large_map);
        EXPECT_EQ(root.size(), compact_capacity + std::size_t{1});
        EXPECT_EQ(root.ref().via.large_map._type, static_cast<uint8_t>(object_type::large_map));
        EXPECT_EQ(root.ref().via.large_map.size, compact_capacity + std::size_t{1});
        EXPECT_EQ(root.ref().via.large_map.capacity, promoted_capacity);
        EXPECT_EQ(root.at(compact_capacity).as<std::uint64_t>(), 42);
        EXPECT_EQ(alloc.last_allocation_bytes(), promoted_capacity * sizeof(detail::object_kv));
        EXPECT_EQ(alloc.last_allocation_alignment(), alignof(detail::object_kv));
        EXPECT_EQ(alloc.last_deallocation_bytes(), compact_capacity * sizeof(detail::object_kv));
        EXPECT_EQ(alloc.last_deallocation_alignment(), alignof(detail::object_kv));
    }
}

TEST(TestObject, ArrayObjectEmplaceBack)
{
    auto root = test::ddwaf_object_da::make_array();
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
        auto root = owned_object::make_array(&alloc);
        EXPECT_EQ(root.type(), object_type::array);
        EXPECT_TRUE(root.is_valid());

        for (unsigned i = 0; i < 20; i++) {
            root.emplace_back(test::ddwaf_object_da::make_string(
                std::to_string(i) + "_012345678901234"s, &alloc));
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
    auto root = test::ddwaf_object_da::make_array(20);
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
            root.emplace_back(test::ddwaf_object_da::make_string(
                std::to_string(i) + "_012345678901234"s, &alloc));
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

    auto root = test::ddwaf_object_da::make_array(20);
    EXPECT_THROW(root.emplace_back(test::ddwaf_object_da::make_string("012345678901234"sv, &alloc)),
        std::runtime_error);
}

TEST(TestObject, EmptyMapObject)
{
    auto root = test::ddwaf_object_da::make_map(0);
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());
    EXPECT_TRUE(root.empty());
}

TEST(TestObject, EmptyMapObjectWithAllocator)
{
    counting_resource alloc;

    {
        auto root = owned_object::make_map(&alloc);
        EXPECT_EQ(root.type(), object_type::map);
        EXPECT_TRUE(root.is_valid());
        EXPECT_TRUE(root.empty());
    }

    EXPECT_EQ(alloc.allocations(), 0);
    EXPECT_EQ(alloc.deallocations(), 0);
}

TEST(TestObject, EmptyPreallocatedMapObject)
{
    auto root = test::ddwaf_object_da::make_map(20);
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
    auto root = test::ddwaf_object_da::make_map();
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
        auto root = owned_object::make_map(&alloc);
        EXPECT_EQ(root.type(), object_type::map);
        EXPECT_TRUE(root.is_valid());

        for (unsigned i = 0; i < 20; i++) {
            root.emplace(std::to_string(i), test::ddwaf_object_da::make_string(
                                                std::to_string(i) + "_012345678901234"s, &alloc));
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
    auto root = test::ddwaf_object_da::make_map(20);
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
            root.emplace(std::to_string(i), test::ddwaf_object_da::make_string(
                                                std::to_string(i) + "_012345678901234"s, &alloc));
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

    auto root = test::ddwaf_object_da::make_map(20);
    EXPECT_THROW(
        root.emplace("key"sv, test::ddwaf_object_da::make_string("012345678901234"sv, &alloc)),
        std::runtime_error);
}

TEST(TestObject, ArrayObjectBuilder)
{
    auto root = object_builder_da::array({"hello", "this", "is", "an", "array"});
    EXPECT_EQ(root.type(), object_type::array);
    EXPECT_TRUE(root.is_valid());
    EXPECT_EQ(root.size(), 5);
}

TEST(TestObject, MapObjectBuilder)
{
    auto root = object_builder_da::map({{"hello"sv, object_builder_da::array({"array", "value"})},
        {"this"sv, "is"sv}, {"an"sv, "array"sv}});
    EXPECT_EQ(root.type(), object_type::map);
    EXPECT_TRUE(root.is_valid());
    EXPECT_EQ(root.size(), 3);
}

TEST(TestObject, HeterogenousArrayObjectBuilder)
{
    auto root = object_builder_da::array({object_builder_da::array({"array", "value"}),
        object_builder_da::map({{"map", "value"}}), "small"sv, "this is a normal string view"sv,
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
    auto root = object_builder_da::map({
        {"array"sv, object_builder_da::array({"array", "value"})},
        {"map"sv, object_builder_da::map({{"map", "value"}})},
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
            {"hello", "this", "is", "an", "array", object_builder_da::array({"hello"})}, &alloc),
        std::runtime_error);
    EXPECT_THROW(object_builder::array({"hello", "this", "is", "an", "array",
                                           object_builder_da::map({{"hello", "bye"}})},
                     &alloc),
        std::runtime_error);

    EXPECT_THROW(object_builder::array({"hello", "this", "is", "an", "array",
                                           object_builder::array({"hello"}, &alloc)},
                     memory::get_default_resource()),
        std::runtime_error);
    EXPECT_THROW(object_builder::array({"hello", "this", "is", "an", "array",
                                           object_builder::map({{"hello", "bye"}}, &alloc)},
                     memory::get_default_resource()),
        std::runtime_error);
}

TEST(TestObject, MapObjectBuilderIncompatibleAllocators)
{
    memory::monotonic_buffer_resource alloc;
    EXPECT_THROW(object_builder::map({{"hello"sv, object_builder_da::array({"array", "value"})},
                                         {"this"sv, "is"sv}, {"an"sv, "array"sv}},
                     &alloc),
        std::runtime_error);
    EXPECT_THROW(object_builder::map({{"hello"sv, object_builder_da::map({{"array", "value"}})},
                                         {"this"sv, "is"sv}, {"an"sv, "array"sv}},
                     &alloc),
        std::runtime_error);

    EXPECT_THROW(
        object_builder::map({{"hello"sv, object_builder::array({"array", "value"}, &alloc)},
                                {"this"sv, "is"sv}, {"an"sv, "array"sv}},
            memory::get_default_resource()),
        std::runtime_error);
    EXPECT_THROW(
        object_builder::map({{"hello"sv, object_builder::map({{"array", "value"}}, &alloc)},
                                {"this"sv, "is"sv}, {"an"sv, "array"sv}},
            memory::get_default_resource()),
        std::runtime_error);
}

TEST(TestObject, ObjectWithNullAllocator)
{
    auto root = object_builder_da::map({
        {"array"sv, object_builder_da::array({"array", "value"})},
        {"map"sv, object_builder_da::map({{"map", "value"}})},
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

    // Create a new owned_object using the internal reference to ensure it's not
    // double freed
    {
        null_counting_resource alloc;
        {
            owned_object other = owned_object{root.ref(), &alloc};
        }
        EXPECT_EQ(alloc.deallocations(), 0);
    }
}

TEST(TestObject, CloneInvalid)
{
    owned_object input = owned_object{};
    auto output = input.clone(memory::get_default_resource());
    EXPECT_TRUE(output.is_invalid());
}

TEST(TestObject, CloneNull)
{
    auto input = owned_object::make_null();

    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::null);
}

TEST(TestObject, CloneBool)
{
    auto input = owned_object::make_boolean(true);

    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::boolean);
    EXPECT_EQ(output.as<bool>(), true);
}

TEST(TestObject, CloneSigned)
{
    auto input = owned_object::make_signed(-5);
    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::int64);
    EXPECT_EQ(output.as<int64_t>(), -5);
}

TEST(TestObject, CloneUnsigned)
{
    auto input = owned_object::make_unsigned(5);
    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::uint64);
    EXPECT_EQ(output.as<uint64_t>(), 5);
}

TEST(TestObject, CloneFloat)
{
    auto input = owned_object::make_float(5.1);
    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::float64);
    EXPECT_EQ(output.as<double>(), 5.1);
}

TEST(TestObject, CloneString)
{
    auto input = test::ddwaf_object_da::make_string("this is a string");
    auto output = input.clone(memory::get_default_resource());
    EXPECT_TRUE(output.is_string());
    EXPECT_EQ(input.as<std::string_view>(), output.as<std::string_view>());
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneSmallString)
{
    auto input = test::ddwaf_object_da::make_string("this");
    auto output = input.clone(memory::get_default_resource());
    EXPECT_TRUE(output.is_string());
    EXPECT_EQ(input.as<std::string_view>(), output.as<std::string_view>());
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneStringLiteral)
{
    auto input = owned_object::make_string_literal(STRL("this"));
    auto output = input.clone(memory::get_default_resource());
    EXPECT_TRUE(output.is_string());
    EXPECT_EQ(input.as<std::string_view>(), output.as<std::string_view>());
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneEmptyArray)
{
    auto input = test::ddwaf_object_da::make_array();
    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::array);
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneEmptyMap)
{
    auto input = test::ddwaf_object_da::make_map();
    auto output = input.clone(memory::get_default_resource());
    EXPECT_EQ(output.type(), object_type::map);
    EXPECT_EQ(input.size(), output.size());
}

TEST(TestObject, CloneArray)
{
    auto input = test::ddwaf_object_da::make_array();
    input.emplace_back(true);
    input.emplace_back("string");
    input.emplace_back(test::ddwaf_object_da::make_signed(5L));

    auto output = input.clone(memory::get_default_resource());
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
    auto input = object_builder_da::map(
        {{"bool", true}, {"string", "string"}, {"signed", test::ddwaf_object_da::make_signed(5)}});

    auto output = input.clone(memory::get_default_resource());
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
    auto input = object_builder_da::map(
        {{"bool", true}, {"string", "string"}, {"signed", test::ddwaf_object_da::make_signed(5)},
            {"array", object_builder_da::array({"1", test::ddwaf_object_da::make_signed(2), "3",
                          test::ddwaf_object_da::make_signed(4)})}});

    auto output = input.clone(memory::get_default_resource());
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
    auto input = object_builder_da::map({{"bool value key ...", true},
        {"string value key", "string value value"},
        {"signed value key", test::ddwaf_object_da::make_signed(5)},
        {"array value key", object_builder_da::array({"1", test::ddwaf_object_da::make_signed(2),
                                "3", test::ddwaf_object_da::make_signed(4)})}});

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
    auto input = object_builder_da::map({{"bool value key ...", true},
        {"string value key", "string value value"},
        {"signed value key", test::ddwaf_object_da::make_signed(5)},
        {"array value key", object_builder_da::array({"1", test::ddwaf_object_da::make_signed(2),
                                "3", test::ddwaf_object_da::make_signed(4)})}});

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
