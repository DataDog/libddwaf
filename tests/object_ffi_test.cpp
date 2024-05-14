// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <gtest/gtest.h>
#include <memory_resource>
#include <string_view>

#include "ddwaf.h"

#define EXPECT_SVEQ(obtained, expected) \
    EXPECT_TRUE(obtained == std::string_view{expected})

#define LSTRARG(str) (str), sizeof((str)) - 1
using namespace std::literals;

namespace {
struct counting_allocator {
    std::size_t alloc{0};
    std::size_t free{0};
    std::pmr::memory_resource *memres{std::pmr::new_delete_resource()};
};

void* counting_alloc(void *udata, size_t size, size_t alignment)
{
    counting_allocator &allocator = *reinterpret_cast<counting_allocator*>(udata);
    allocator.alloc++;
    return allocator.memres->allocate(size, alignment);
}

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
void counting_free(void *udata, void *ptr, size_t size, size_t alignment)
{
    counting_allocator &allocator = *reinterpret_cast<counting_allocator*>(udata);
    allocator.free++;
    allocator.memres->deallocate(ptr, size, alignment);
}

TEST(ObjectFfi, InvalidConstructor)
{
    ddwaf_object obj;
    ddwaf_object_set_invalid(&obj);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_INVALID);
}

TEST(ObjectFfi, NullConstructor)
{
    ddwaf_object obj;
    ddwaf_object_set_null(&obj);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_NULL);
}

TEST(ObjectFfi, BooleanConstructor)
{
    {
        ddwaf_object obj;
        ddwaf_object_set_bool(&obj, true);
        EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_BOOL);
        EXPECT_TRUE(ddwaf_object_get_bool(&obj));
    }
    {
        ddwaf_object obj;
        ddwaf_object_set_bool(&obj, false);
        EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_BOOL);
        EXPECT_FALSE(ddwaf_object_get_bool(&obj));
    }
}

TEST(ObjectFfi, UnsignedConstructor)
{
    auto value = std::numeric_limits<uint64_t>::max();
    ddwaf_object obj;
    ddwaf_object_set_unsigned(&obj, value);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_UNSIGNED);
    EXPECT_EQ(ddwaf_object_get_unsigned(&obj), value);
}

TEST(ObjectFfi, SignedConstructor)
{
    auto value = std::numeric_limits<int64_t>::min();
    ddwaf_object obj;
    ddwaf_object_set_signed(&obj, value);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_SIGNED);
    EXPECT_EQ(ddwaf_object_get_signed(&obj), value);
}

TEST(ObjectFfi, FloatConstructor)
{
    auto value = std::numeric_limits<double>::min();
    ddwaf_object obj;
    ddwaf_object_set_float(&obj, value);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_FLOAT);
    EXPECT_EQ(ddwaf_object_get_float(&obj), value);
}

TEST(ObjectFfi, ConstStringConstructor)
{
    auto value = "hello"sv;
    ddwaf_object obj;
    ddwaf_object_set_const_string(&obj, value.data(), value.size());
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_CONST_STRING);
    EXPECT_EQ(ddwaf_object_get_length(&obj), value.size());
    EXPECT_EQ(ddwaf_object_get_string(&obj), value.data());

    std::string_view result{ddwaf_object_get_string(&obj), ddwaf_object_get_length(&obj)};
    EXPECT_SVEQ(value, result);
}

TEST(ObjectFfi, SmallStringConstructor)
{
    auto value = "hello"sv;
    ddwaf_object obj;
    ddwaf_object_set_string(&obj, value.data(), value.size(), nullptr);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_SMALL_STRING);
    EXPECT_EQ(ddwaf_object_get_length(&obj), value.size());

    std::string_view result{ddwaf_object_get_string(&obj), ddwaf_object_get_length(&obj)};
    EXPECT_SVEQ(value, result);
}

TEST(ObjectFfi, StringConstructor)
{
    auto value = "hello world!"sv;
    ddwaf_object obj;
    ddwaf_object_set_string(&obj, value.data(), value.size(), nullptr);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_STRING);
    EXPECT_EQ(ddwaf_object_get_length(&obj), value.size());

    std::string_view result{ddwaf_object_get_string(&obj), ddwaf_object_get_length(&obj)};
    EXPECT_SVEQ(value, result);

    ddwaf_object_destroy(&obj, nullptr);
}

TEST(ObjectFfi, StringConstructorUserAllocator)
{
    constexpr auto value = "hello world!"sv;

    counting_allocator underlying_alloc;
    auto *alloc = ddwaf_allocator_init(reinterpret_cast<void*>(&underlying_alloc), counting_alloc, counting_free);
    ASSERT_NE(alloc, nullptr);

    ddwaf_object obj;
    ddwaf_object_set_string(&obj, value.data(), value.size(), alloc);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_STRING);
    EXPECT_EQ(ddwaf_object_get_length(&obj), value.size());
    EXPECT_EQ(underlying_alloc.alloc, 1);

    std::string_view result{ddwaf_object_get_string(&obj), ddwaf_object_get_length(&obj)};
    EXPECT_SVEQ(value, result);

    ddwaf_object_destroy(&obj, alloc);

    EXPECT_EQ(underlying_alloc.free, 1);
    ddwaf_allocator_destroy(alloc);
}

TEST(ObjectFfi, ArrayConstructor)
{
    ddwaf_object obj;
    ddwaf_object_set_array(&obj, 8, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), 8);
    ddwaf_object_destroy(&obj, nullptr);
}

TEST(ObjectFfi, ArrayConstructorUserAllocator)
{
    counting_allocator underlying_alloc;
    auto *alloc = ddwaf_allocator_init(reinterpret_cast<void*>(&underlying_alloc), counting_alloc, counting_free);
    ASSERT_NE(alloc, nullptr);

    ddwaf_object obj;
    ddwaf_object_set_array(&obj, 8, alloc);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), 8);
    EXPECT_EQ(underlying_alloc.alloc, 1);

    ddwaf_object_destroy(&obj, alloc);
    EXPECT_EQ(underlying_alloc.free, 1);
    ddwaf_allocator_destroy(alloc);
}

TEST(ObjectFfi, MapConstructor)
{
    ddwaf_object obj;
    ddwaf_object_set_map(&obj, 8, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), 8);
    ddwaf_object_destroy(&obj, nullptr);
}

TEST(ObjectFfi, MapConstructorUserAllocator)
{
    counting_allocator underlying_alloc;
    auto *alloc = ddwaf_allocator_init(reinterpret_cast<void*>(&underlying_alloc), counting_alloc, counting_free);
    ASSERT_NE(alloc, nullptr);

    ddwaf_object obj;
    ddwaf_object_set_map(&obj, 8, alloc);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), 8);
    EXPECT_EQ(underlying_alloc.alloc, 1);

    ddwaf_object_destroy(&obj, alloc);
    EXPECT_EQ(underlying_alloc.free, 1);
    ddwaf_allocator_destroy(alloc);
}

TEST(ObjectFfi, ArrayInsert)
{
    unsigned count = 8;

    ddwaf_object obj;
    ddwaf_object_set_array(&obj, count, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);

    for (unsigned i = 0; i < count; ++i ) {
        auto *slot = ddwaf_object_insert(&obj);
        ddwaf_object_set_invalid(slot);
        EXPECT_EQ(ddwaf_object_get_size(&obj), i + 1);
    }

    {
        auto *slot = ddwaf_object_insert(&obj);
        EXPECT_EQ(slot, nullptr);
    }

    EXPECT_EQ(ddwaf_object_get_size(&obj), count);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);

    for (unsigned i = 0; i < ddwaf_object_get_size(&obj); ++i) {
        const auto *value = ddwaf_object_get_index(&obj, i, nullptr);
        ASSERT_NE(value, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(value), DDWAF_OBJ_INVALID);
    }

    ddwaf_object_destroy(&obj, nullptr);
}

TEST(ObjectFfi, ArrayInsertUserAllocator)
{
    constexpr unsigned count = 8;

    counting_allocator underlying_alloc;
    auto *alloc = ddwaf_allocator_init(reinterpret_cast<void*>(&underlying_alloc), counting_alloc, counting_free);
    ASSERT_NE(alloc, nullptr);

    ddwaf_object obj;
    ddwaf_object_set_array(&obj, count, alloc);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);
    EXPECT_EQ(underlying_alloc.alloc, 1);

    for (unsigned i = 0; i < count; ++i ) {
        auto *slot = ddwaf_object_insert(&obj);
        ddwaf_object_set_string(slot, LSTRARG("long string..."), alloc);
        EXPECT_EQ(ddwaf_object_get_size(&obj), i + 1);
    }
    EXPECT_EQ(underlying_alloc.alloc, 9);

    EXPECT_EQ(ddwaf_object_get_size(&obj), count);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);

    ddwaf_object_destroy(&obj, alloc);
    EXPECT_EQ(underlying_alloc.free, 9);
    ddwaf_allocator_destroy(alloc);
}

TEST(ObjectFfi, ArrayInsertHeterogenous)
{
    ddwaf_object obj;
    ddwaf_object_set_array(&obj, 11, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_ARRAY);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), 11);

    auto *slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_invalid(slot);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 1);

    slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_null(slot);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 2);

    slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_bool(slot, true);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 3);

    slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_signed(slot, -42);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 4);

    slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_unsigned(slot, 42);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 5);

    slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_float(slot, 42.42);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 6);

    slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_const_string(slot, "hello", sizeof("hello") - 1);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 7);

    slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_string(slot, "hello", sizeof("hello") - 1, nullptr);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 8);

    slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_string(slot, "hello world!", sizeof("hello world!") - 1, nullptr);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 9);

    slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_array(slot, 1, nullptr);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 10);

    auto *child_slot = ddwaf_object_insert(slot);
    ddwaf_object_set_string(child_slot, "hello world!", sizeof("hello world!") - 1, nullptr);

    slot = ddwaf_object_insert(&obj);
    ddwaf_object_set_map(slot, 2, nullptr);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 11);

    child_slot = ddwaf_object_insert_key(slot, "key", sizeof("key") - 1, nullptr);
    ddwaf_object_set_string(child_slot, "hello world!", sizeof("hello world!") - 1, nullptr);

    child_slot = ddwaf_object_insert_const_key(slot, "key", sizeof("key") - 1);
    ddwaf_object_set_string(child_slot, "hello world!", sizeof("hello world!") - 1, nullptr);

    EXPECT_EQ(ddwaf_object_get_size(&obj), ddwaf_object_get_capacity(&obj));

    std::array<ddwaf_object_type, 11> types {
        DDWAF_OBJ_INVALID, DDWAF_OBJ_NULL, DDWAF_OBJ_BOOL, DDWAF_OBJ_SIGNED, DDWAF_OBJ_UNSIGNED, DDWAF_OBJ_FLOAT, DDWAF_OBJ_CONST_STRING, DDWAF_OBJ_SMALL_STRING, DDWAF_OBJ_STRING, DDWAF_OBJ_ARRAY, DDWAF_OBJ_MAP};
    for (unsigned i = 0; i < ddwaf_object_get_size(&obj); ++i) {
        const auto *value = ddwaf_object_get_index(&obj, i, nullptr);
        ASSERT_NE(value, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(value), types.at(i));
    }

    // Check child array
    {
        const auto *array = ddwaf_object_get_index(&obj, 9, nullptr);
        ASSERT_NE(array, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(array), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(array), 1);
        EXPECT_EQ(ddwaf_object_get_capacity(array), 1);

        const auto *child = ddwaf_object_get_index(array, 0, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(child), DDWAF_OBJ_STRING);

        std::string_view result{ddwaf_object_get_string(child), ddwaf_object_get_length(child)};
        EXPECT_SVEQ(result, "hello world!");
    }

    // Check child map
    {
        const auto *map = ddwaf_object_get_index(&obj, 10, nullptr);
        ASSERT_NE(map, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(map), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(map), 2);
        EXPECT_EQ(ddwaf_object_get_capacity(map), 2);

        const ddwaf_object *child_key{nullptr};
        const auto *child = ddwaf_object_get_index(map, 0, &child_key);
        EXPECT_EQ(ddwaf_object_get_type(child), DDWAF_OBJ_STRING);
        EXPECT_EQ(ddwaf_object_get_type(child_key), DDWAF_OBJ_SMALL_STRING);

        std::string_view result{ddwaf_object_get_string(child), ddwaf_object_get_length(child)};
        std::string_view key{ddwaf_object_get_string(child_key), ddwaf_object_get_length(child_key)};
        EXPECT_SVEQ(result, "hello world!");
        EXPECT_SVEQ(key, "key");

        child = ddwaf_object_get_index(map, 1, &child_key);
        EXPECT_EQ(ddwaf_object_get_type(child), DDWAF_OBJ_STRING);
        EXPECT_EQ(ddwaf_object_get_type(child_key), DDWAF_OBJ_CONST_STRING);

        EXPECT_SVEQ(result, "hello world!");
        EXPECT_SVEQ(key, "key");
    }

    ddwaf_object_destroy(&obj, nullptr);
}

TEST(ObjectFfi, MapInsertKey)
{
    unsigned count = 8;
    ddwaf_object obj;
    ddwaf_object_set_map(&obj, 8, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);

    std::string_view exp_key = "key_larger_than_11_bytes";
    for (unsigned i = 0; i < count; ++i ) {
        auto *slot = ddwaf_object_insert_key(&obj, exp_key.data(), exp_key.size(), nullptr);
        ddwaf_object_set_invalid(slot);
        EXPECT_EQ(ddwaf_object_get_size(&obj), i + 1);
    }

    {
        auto *slot = ddwaf_object_insert(&obj);
        EXPECT_EQ(slot, nullptr);
    }

    EXPECT_EQ(ddwaf_object_get_size(&obj), count);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);

    for (unsigned i = 0; i < ddwaf_object_get_size(&obj); ++i) {
        const ddwaf_object *key = nullptr;
        const auto *value = ddwaf_object_get_index(&obj, i, &key);
        ASSERT_NE(value, nullptr);
        ASSERT_NE(key, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(value), DDWAF_OBJ_INVALID);
        EXPECT_EQ(ddwaf_object_get_type(key), DDWAF_OBJ_STRING);

        std::string_view key_sv{ddwaf_object_get_string(key), ddwaf_object_get_length(key)};
        EXPECT_SVEQ(key_sv, exp_key);
    }

    ddwaf_object_destroy(&obj, nullptr);
}

TEST(ObjectFfi, MapInsertKeyUserAllocator)
{
    constexpr unsigned count = 8;

    counting_allocator underlying_alloc;
    auto *alloc = ddwaf_allocator_init(reinterpret_cast<void*>(&underlying_alloc), counting_alloc, counting_free);
    ASSERT_NE(alloc, nullptr);

    ddwaf_object obj;
    ddwaf_object_set_map(&obj, 8, alloc);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);
    EXPECT_EQ(underlying_alloc.alloc, 1);

    std::string_view exp_key = "key_larger_than_11_bytes";
    for (unsigned i = 0; i < count; ++i ) {
        auto *slot = ddwaf_object_insert_key(&obj, exp_key.data(), exp_key.size(), alloc);
        ddwaf_object_set_string(slot, LSTRARG("long string..."), alloc);
        EXPECT_EQ(ddwaf_object_get_size(&obj), i + 1);
    }

    EXPECT_EQ(ddwaf_object_get_size(&obj), count);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);
    EXPECT_EQ(underlying_alloc.alloc, 17);

    ddwaf_object_destroy(&obj, alloc);
    EXPECT_EQ(underlying_alloc.free, 17);
    ddwaf_allocator_destroy(alloc);
}



TEST(ObjectFfi, MapInsertSmallKey)
{
    unsigned count = 8;
    ddwaf_object obj;
    ddwaf_object_set_map(&obj, 8, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);

    std::string_view exp_key = "key";
    for (unsigned i = 0; i < count; ++i ) {
        auto *slot = ddwaf_object_insert_key(&obj, exp_key.data(), exp_key.size(), nullptr);
        ddwaf_object_set_invalid(slot);
        EXPECT_EQ(ddwaf_object_get_size(&obj), i + 1);
    }

    {
        auto *slot = ddwaf_object_insert(&obj);
        EXPECT_EQ(slot, nullptr);
    }

    EXPECT_EQ(ddwaf_object_get_size(&obj), count);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);

    for (unsigned i = 0; i < ddwaf_object_get_size(&obj); ++i) {
        const ddwaf_object *key = nullptr;
        const auto *value = ddwaf_object_get_index(&obj, i, &key);
        ASSERT_NE(value, nullptr);
        ASSERT_NE(key, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(value), DDWAF_OBJ_INVALID);
        EXPECT_EQ(ddwaf_object_get_type(key), DDWAF_OBJ_SMALL_STRING);

        std::string_view key_sv{ddwaf_object_get_string(key), ddwaf_object_get_length(key)};
        EXPECT_SVEQ(key_sv, exp_key);
    }

    ddwaf_object_destroy(&obj, nullptr);
}

TEST(ObjectFfi, MapInsertConstKey)
{
    unsigned count = 8;
    ddwaf_object obj;
    ddwaf_object_set_map(&obj, 8, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);

    std::string_view exp_key = "key";
    for (unsigned i = 0; i < count; ++i ) {
        auto *slot = ddwaf_object_insert_const_key(&obj, exp_key.data(), exp_key.size());
        ddwaf_object_set_invalid(slot);
        EXPECT_EQ(ddwaf_object_get_size(&obj), i + 1);
    }

    {
        auto *slot = ddwaf_object_insert(&obj);
        EXPECT_EQ(slot, nullptr);
    }

    EXPECT_EQ(ddwaf_object_get_size(&obj), count);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), count);

    for (unsigned i = 0; i < ddwaf_object_get_size(&obj); ++i) {
        const ddwaf_object *key = nullptr;
        const auto *value = ddwaf_object_get_index(&obj, i, &key);
        ASSERT_NE(value, nullptr);
        ASSERT_NE(key, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(value), DDWAF_OBJ_INVALID);
        EXPECT_EQ(ddwaf_object_get_type(key), DDWAF_OBJ_CONST_STRING);
        EXPECT_EQ(ddwaf_object_get_string(key), exp_key.data());
        EXPECT_EQ(ddwaf_object_get_length(key), exp_key.size());

        std::string_view key_sv{ddwaf_object_get_string(key), ddwaf_object_get_length(key)};
        EXPECT_SVEQ(key_sv, exp_key);
    }

    ddwaf_object_destroy(&obj, nullptr);
}

TEST(ObjectFfi, MapInsertHeterogenous)
{
    ddwaf_object obj;
    ddwaf_object_set_map(&obj, 11, nullptr);
    EXPECT_EQ(ddwaf_object_get_type(&obj), DDWAF_OBJ_MAP);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 0);
    EXPECT_EQ(ddwaf_object_get_capacity(&obj), 11);

    auto *slot = ddwaf_object_insert_key(&obj, LSTRARG("0"), nullptr);
    ddwaf_object_set_invalid(slot);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 1);

    slot = ddwaf_object_insert_key(&obj, LSTRARG("1"), nullptr);
    ddwaf_object_set_null(slot);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 2);

    slot = ddwaf_object_insert_key(&obj, LSTRARG("2"), nullptr);
    ddwaf_object_set_bool(slot, true);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 3);

    slot = ddwaf_object_insert_key(&obj, LSTRARG("3"), nullptr);
    ddwaf_object_set_signed(slot, -42);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 4);

    slot = ddwaf_object_insert_key(&obj, LSTRARG("4"), nullptr);
    ddwaf_object_set_unsigned(slot, 42);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 5);

    slot = ddwaf_object_insert_key(&obj, LSTRARG("5"), nullptr);
    ddwaf_object_set_float(slot, 42.42);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 6);

    slot = ddwaf_object_insert_key(&obj, LSTRARG("6"), nullptr);
    ddwaf_object_set_const_string(slot, "hello", sizeof("hello") - 1);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 7);

    slot = ddwaf_object_insert_key(&obj, LSTRARG("7"), nullptr);
    ddwaf_object_set_string(slot, "hello", sizeof("hello") - 1, nullptr);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 8);

    slot = ddwaf_object_insert_key(&obj, LSTRARG("8"), nullptr);
    ddwaf_object_set_string(slot, "hello world!", sizeof("hello world!") - 1, nullptr);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 9);

    slot = ddwaf_object_insert_key(&obj, LSTRARG("9"), nullptr);
    ddwaf_object_set_array(slot, 1, nullptr);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 10);

    auto *child_slot = ddwaf_object_insert(slot);
    ddwaf_object_set_string(child_slot, "hello world!", sizeof("hello world!") - 1, nullptr);

    slot = ddwaf_object_insert_key(&obj, LSTRARG("10"), nullptr);
    ddwaf_object_set_map(slot, 2, nullptr);
    EXPECT_EQ(ddwaf_object_get_size(&obj), 11);

    child_slot = ddwaf_object_insert_key(slot, "key", sizeof("key") - 1, nullptr);
    ddwaf_object_set_string(child_slot, "hello world!", sizeof("hello world!") - 1, nullptr);

    child_slot = ddwaf_object_insert_const_key(slot, "key", sizeof("key") - 1);
    ddwaf_object_set_string(child_slot, "hello world!", sizeof("hello world!") - 1, nullptr);

    EXPECT_EQ(ddwaf_object_get_size(&obj), ddwaf_object_get_capacity(&obj));

    std::array<ddwaf_object_type, 11> types {DDWAF_OBJ_INVALID, DDWAF_OBJ_NULL, DDWAF_OBJ_BOOL,
        DDWAF_OBJ_SIGNED, DDWAF_OBJ_UNSIGNED, DDWAF_OBJ_FLOAT, DDWAF_OBJ_CONST_STRING,
        DDWAF_OBJ_SMALL_STRING, DDWAF_OBJ_STRING, DDWAF_OBJ_ARRAY, DDWAF_OBJ_MAP};
    for (unsigned i = 0; i < ddwaf_object_get_size(&obj); ++i) {
        const ddwaf_object *child_key{nullptr};
        const auto *value = ddwaf_object_get_index(&obj, i, &child_key);
        ASSERT_NE(value, nullptr);
        ASSERT_NE(child_key, nullptr);

        EXPECT_EQ(ddwaf_object_get_type(value), types.at(i));
        std::string_view key{ddwaf_object_get_string(child_key), ddwaf_object_get_length(child_key)};
        EXPECT_EQ(std::to_string(i), key);
    }

    // Check child array
    {
        const auto *array = ddwaf_object_get_index(&obj, 9, nullptr);
        ASSERT_NE(array, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(array), DDWAF_OBJ_ARRAY);
        EXPECT_EQ(ddwaf_object_get_size(array), 1);
        EXPECT_EQ(ddwaf_object_get_capacity(array), 1);

        const auto *child = ddwaf_object_get_index(array, 0, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(child), DDWAF_OBJ_STRING);

        std::string_view result{ddwaf_object_get_string(child), ddwaf_object_get_length(child)};
        EXPECT_SVEQ(result, "hello world!");
    }

    // Check child map
    {
        const auto *map = ddwaf_object_get_index(&obj, 10, nullptr);
        ASSERT_NE(map, nullptr);
        EXPECT_EQ(ddwaf_object_get_type(map), DDWAF_OBJ_MAP);
        EXPECT_EQ(ddwaf_object_get_size(map), 2);
        EXPECT_EQ(ddwaf_object_get_capacity(map), 2);

        const ddwaf_object *child_key{nullptr};
        const auto *child = ddwaf_object_get_index(map, 0, &child_key);
        EXPECT_EQ(ddwaf_object_get_type(child), DDWAF_OBJ_STRING);
        EXPECT_EQ(ddwaf_object_get_type(child_key), DDWAF_OBJ_SMALL_STRING);

        std::string_view result{ddwaf_object_get_string(child), ddwaf_object_get_length(child)};
        std::string_view key{ddwaf_object_get_string(child_key), ddwaf_object_get_length(child_key)};
        EXPECT_SVEQ(result, "hello world!");
        EXPECT_SVEQ(key, "key");

        child = ddwaf_object_get_index(map, 1, &child_key);
        EXPECT_EQ(ddwaf_object_get_type(child), DDWAF_OBJ_STRING);
        EXPECT_EQ(ddwaf_object_get_type(child_key), DDWAF_OBJ_CONST_STRING);

        EXPECT_SVEQ(result, "hello world!");
        EXPECT_SVEQ(key, "key");
    }

    ddwaf_object_destroy(&obj, nullptr);
}

} // namespace
