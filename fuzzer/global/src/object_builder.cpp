// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdio>
#include <cstring>

#include "helpers.hpp"
#include "object_builder.hpp"

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

void pop_string(Data *data, ddwaf_object *object)
{
    if (data->position >= data->size) {
        ddwaf_object_stringl(object, "", 0);
        return;
    }

    char *result = (char *)(data->bytes + data->position);
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
        *object = {.type = DDWAF_OBJ_STRING, .via{.str{.size = 0, .ptr = nullptr}}};
    } else {
        ddwaf_object_stringl(object, result, size);
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
uint8_t popByte(Data *data)
{
    uint8_t result = 0;

    popBytes(data, &result, 1);

    return result;
}

ddwaf_object create_object(Data *data, size_t deep);

void build_map(Data *data, ddwaf_object *object, size_t deep)
{
    ddwaf_object_map(object);
    ddwaf_object key;
    ddwaf_object item;

    uint8_t size = popSize(data);

    if (deep == 0) {
        size = 0;
    }

    for (uint8_t i = 0; i < size && data->position < data->size; i++) {
        auto null_key = popBoolean(data);

        item = create_object(data, deep - 1);

        if (!null_key) {
            pop_string(data, &key);
            std::size_t key_len;
            const char *key_ptr = ddwaf_object_get_string(&key, &key_len);

            if (key.type == DDWAF_OBJ_STRING || key.type == DDWAF_OBJ_LARGE_STRING) {
                if (!ddwaf_object_map_addl_nc(object, key_ptr, key_len, &item)) {
                    ddwaf_object_free(&item);
                }
            } else if (key.type == DDWAF_OBJ_SMALL_STRING) {
                if (!ddwaf_object_map_addl(object, key_ptr, key_len, &item)) {
                    ddwaf_object_free(&item);
                }
            }
        } else {
            if (!ddwaf_object_map_addl(object, "", 0, &item)) {
                ddwaf_object_free(&item);
            } else {
                auto index = static_cast<std::size_t>(ddwaf_object_size(object) - 1);
                auto &key = object->via.map.ptr[index].key;
                if (key.type == DDWAF_OBJ_STRING) {
                    // NOLINTNEXTLINE(hicpp-no-malloc)
                    free((void *)key.via.str.ptr);
                    // Null but not malformed
                    key.via.str.ptr = nullptr;
                    key.via.str.size = 0;
                }
            }
        }
    }
}

void build_array(Data *data, ddwaf_object *object, size_t deep)
{
    ddwaf_object_array(object);

    uint8_t size = popSize(data);
    ddwaf_object item;

    if (deep == 0) {
        size = 0;
    }

    for (uint8_t i = 0; i < size && data->position < data->size; i++) {
        item = create_object(data, deep - 1);
        if (!ddwaf_object_array_add(object, &item)) {
            ddwaf_object_free(&item);
        }
    }
}

ddwaf_object create_object(Data *data, size_t deep)
{
    ddwaf_object result;
    uint8_t selector = popSelector(data, 9);

    switch (selector) {
    case 8:
        ddwaf_object_invalid(&result);
        break;
    case 7:
        ddwaf_object_null(&result);
        break;
    case 6:
        ddwaf_object_float(&result, popDouble(data));
        break;
    case 5:
        ddwaf_object_bool(&result, popBoolean(data));
        break;
    case 4:
        ddwaf_object_unsigned(&result, popUnsignedInteger(data));
        break;
    case 3:
        ddwaf_object_signed(&result, popInteger(data));
        break;
    case 2:
        pop_string(data, &result);
        break;
    case 1:
        build_array(data, &result, deep);
        break;
    case 0:
        build_map(data, &result, deep);
        break;
    }

    return result;
}

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

    ddwaf_object result;
    build_map(&data, &result, 30);

    if (verbose) {
        print_object(result);
    }

    return result;
}
