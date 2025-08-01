// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdio>
#include <cstring>

#include "ddwaf.h"
#include "helpers.hpp"
#include "object_builder.hpp"

// NOLINTBEGIN(misc-no-recursion)
namespace {
struct Data {
    const uint8_t *bytes{nullptr};
    size_t size{0};
    size_t position{0};
};

uint8_t popSize(Data *data)
{
    if (data->position >= data->size) {
        return 0;
    }

    uint8_t size = data->bytes[data->position];
    data->position++;

    return size;
}

uint8_t popSelector(Data *data, uint8_t maximumValue) { return popSize(data) % maximumValue; }

void popBytes(Data *data, void *dest, uint8_t n)
{
    if (data->position + n - 1 >= data->size) {
        data->position = data->size;
        return;
    }

    memcpy(dest, data->bytes + data->position, n);

    data->position += n;
}

bool popBoolean(Data *data)
{
    uint8_t result = 0;
    popBytes(data, &result, 1);
    return (result % 2) == 0;
}

void pop_string(Data *data, ddwaf_object *object, ddwaf_allocator &alloc)
{
    if (data->position >= data->size) {
        ddwaf_object_set_string_literal(object, "", 0);
        return;
    }

    // NOLINTNEXTLINE-
    char *result = reinterpret_cast<char *>(const_cast<uint8_t *>(data->bytes + data->position));
    size_t size = 0;

    // reserve this useless char for end of string
    uint8_t ENDOFSTRING = 31; // unit separator

    while (data->position < data->size && data->bytes[data->position] != ENDOFSTRING) {
        size++;
        data->position++;
    }

    if (data->position < data->size) {
        data->position++; // here, data->bytes[data->position] == ENDOFSTRING
    }

    // sometimes, send NULL
    if (popBoolean(data)) {
        *object = {.via{.str{.type = DDWAF_OBJ_STRING, .size = 0, .ptr = nullptr}}};
    } else {
        ddwaf_object_set_string(object, result, size, alloc);
    }
}

uint64_t popUnsignedInteger(Data *data)
{
    uint64_t result = 0;

    popBytes(data, &result, 8);

    return result;
}

double popDouble(Data *data)
{
    double result = 0;

    popBytes(data, &result, 8);

    return result;
}

int64_t popInteger(Data *data)
{
    int64_t result = 0;

    popBytes(data, &result, 8);

    return result;
}

uint16_t popUInt16(Data *data)
{
    uint16_t result = 0;

    popBytes(data, &result, 2);

    return result;
}
void create_object(Data *data, ddwaf_object *object, ddwaf_allocator alloc, size_t depth);

void build_map(Data *data, ddwaf_object *object, ddwaf_allocator alloc, size_t depth)
{
    uint8_t size = popSize(data);

    if (depth == 0) {
        size = 0;
    }

    ddwaf_object_set_map(object, size, alloc);
    for (uint8_t i = 0; i < size && data->position < data->size; i++) {
        auto null_key = popBoolean(data);

        ddwaf_object *child = nullptr;
        if (!null_key) {
            ddwaf_object key;
            pop_string(data, &key, alloc);

            std::size_t key_len;
            const char *key_ptr = ddwaf_object_get_string(&key, &key_len);

            if (ddwaf_object_get_type(&key) == DDWAF_OBJ_STRING) {
                child = ddwaf_object_insert_key_nocopy(object, key_ptr, key_len, alloc);
            } else if (ddwaf_object_get_type(&key) == DDWAF_OBJ_SMALL_STRING) {
                child = ddwaf_object_insert_key(object, key_ptr, key_len, alloc);
            }
        } else {
            child = ddwaf_object_insert_literal_key(object, "", 0, alloc);
        }

        create_object(data, child, alloc, depth - 1);
    }
}

void build_array(Data *data, ddwaf_object *object, ddwaf_allocator alloc, size_t depth)
{
    uint8_t size = popSize(data);
    if (depth == 0) {
        size = 0;
    }

    ddwaf_object_set_array(object, size, alloc);

    for (uint8_t i = 0; i < size && data->position < data->size; i++) {
        auto *child = ddwaf_object_insert(object, alloc);
        create_object(data, child, alloc, depth - 1);
    }
}

void create_object(Data *data, ddwaf_object *object, ddwaf_allocator alloc, size_t depth)
{
    switch (popSelector(data, 9)) {
    case 7:
        ddwaf_object_set_null(object);
        break;
    case 6:
        ddwaf_object_set_float(object, popDouble(data));
        break;
    case 5:
        ddwaf_object_set_bool(object, popBoolean(data));
        break;
    case 4:
        ddwaf_object_set_unsigned(object, popUnsignedInteger(data));
        break;
    case 3:
        ddwaf_object_set_signed(object, popInteger(data));
        break;
    case 2:
        pop_string(data, object, alloc);
        break;
    case 1:
        build_array(data, object, alloc, depth);
        break;
    case 0:
        build_map(data, object, alloc, depth);
        break;
    case 8:
    default:
        ddwaf_object_set_invalid(object);
        break;
    }
}

} // namespace

ddwaf_object build_object(
    const uint8_t *bytes, size_t size, bool verbose, bool fuzzTimeout, size_t *timeLeftInMs)
{
    Data data;

    data.bytes = bytes;
    data.size = size;

    if (fuzzTimeout) {
        *timeLeftInMs = (size_t)popUInt16(&data);
    } else {
        *timeLeftInMs = 200000; // 200ms
    }

    ddwaf_allocator alloc = ddwaf_get_default_allocator();
    ddwaf_object result;
    build_map(&data, &result, alloc, 30);

    if (verbose) {
        print_object(result);
    }

    return result;
}
// NOLINTEND(misc-no-recursion)
