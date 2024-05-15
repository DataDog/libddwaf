// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef DDWAF_OBJECT_H
#define DDWAF_OBJECT_H

#ifdef __cplusplus
#  include <cstdint>
#  include <cstdlib>
extern "C"
{
#else
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#endif
// Constants
#define DDWAF_OBJ_SSTR_SIZE 11

/**
 * @enum ddwaf_object_type
 *
 * Specifies the type of a ddwaf::object.
 *
 * CCCSSSSS
 *    -     String
 *    ----- Scalar
 * ---      Container
 * -------  Non-Null
 */
enum _ddwaf_object_type {
    DDWAF_OBJ_INVALID = 0x00, // 0b00000000
    DDWAF_OBJ_NULL = 0x01, // 0b00000001
    // invalid == !(type & 0xFE)
    DDWAF_OBJ_BOOL = 0x02, // 0b00000010
    DDWAF_OBJ_SIGNED = 0x03, // 0b00000011
    DDWAF_OBJ_UNSIGNED = 0x04, // 0b00000100
    DDWAF_OBJ_FLOAT = 0x05, // 0b00000101
    DDWAF_OBJ_REFERENCE = 0x06, // 0b00000110
    DDWAF_OBJ_STRING = 0x10, // 0b00010000
    DDWAF_OBJ_CONST_STRING = 0x11, // 0b00010001
    DDWAF_OBJ_SMALL_STRING = 0x12, // 0b00010010
    // string == (type & 0x10) != 0
    // scalar == (type & 0x1E) != 0
    DDWAF_OBJ_ARRAY = 0x20, // 0b00100000
    DDWAF_OBJ_MAP = 0x40, // 0b01000000
    // container == (type & 0xE0) != 0
};

#ifdef __cplusplus
namespace std::pmr { class memory_resource; }
using ddwaf_object = struct _ddwaf_object;
using ddwaf_object_kv = struct _ddwaf_object_kv;
using ddwaf_allocator = std::pmr::memory_resource;
using ddwaf_object_type = enum _ddwaf_object_type;
using ddwaf_alloc_fn_type = void* (void *, size_t size, size_t alignment);
using ddwaf_free_fn_type = void (void *, void *, size_t size, size_t alignment);
#else
typedef struct _ddwaf_object ddwaf_object;
typedef struct _ddwaf_object_kv ddwaf_object_kv;
typedef struct _ddwaf_allocator ddwaf_allocator;
typedef enum _ddwaf_object_type ddwaf_object_type;
#endif

struct __attribute__((packed)) _ddwaf_object {
    union __attribute__((packed)) {
        bool b8;
        uint64_t u64;
        int64_t i64;
        double f64;
        ddwaf_object_kv *map;
        ddwaf_object *array;
        char *str;
        char sstr[DDWAF_OBJ_SSTR_SIZE];
        const char *cstr;
        ddwaf_object *ref;
    } via;
    uint8_t type;
    union __attribute__((packed)) {
        struct __attribute__((packed)) {
            uint16_t capacity;
            uint16_t size;
        };
        uint32_t length;
    };
};

struct __attribute__((packed)) _ddwaf_object_kv {
    ddwaf_object key;
    ddwaf_object val;
};

// Allocator constructors and destructor
ddwaf_allocator* ddwaf_allocator_init_default();

ddwaf_allocator* ddwaf_allocator_init(void *user_data, ddwaf_alloc_fn_type *alloc_fn, ddwaf_free_fn_type *free_fn);
void ddwaf_allocator_destroy(ddwaf_allocator *alloc);

// Memory management - alloc / free
ddwaf_object *ddwaf_object_alloc(ddwaf_allocator *alloc);
void ddwaf_object_free(ddwaf_object *object, ddwaf_allocator *alloc);

// Destructors
void ddwaf_object_destroy(ddwaf_object *object, ddwaf_allocator *alloc);

// Constructors
bool ddwaf_object_set_invalid(ddwaf_object *object);
bool ddwaf_object_set_null(ddwaf_object *object);
bool ddwaf_object_set_bool(ddwaf_object *object, bool value);
bool ddwaf_object_set_signed(ddwaf_object *object, int64_t value);
bool ddwaf_object_set_unsigned(ddwaf_object *object, uint64_t value);
bool ddwaf_object_set_float(ddwaf_object *object, double value);

bool ddwaf_object_set_string(
    ddwaf_object *object, const char *str, uint32_t length, ddwaf_allocator *alloc);
bool ddwaf_object_set_string_nocopy(
    ddwaf_object *object, char *str, uint32_t length);

bool ddwaf_object_set_const_string(ddwaf_object *object, const char *str, uint32_t length);

bool ddwaf_object_set_array(ddwaf_object *object, uint16_t capacity, ddwaf_allocator *alloc);
bool ddwaf_object_set_map(ddwaf_object *object, uint16_t capacity, ddwaf_allocator *alloc);

// Array and map insertion functions
// TODO these functions need an allocator
ddwaf_object *ddwaf_object_insert(ddwaf_object *object);
ddwaf_object *ddwaf_object_insert_key(
    ddwaf_object *object, const char *key, uint32_t length, ddwaf_allocator *alloc);
ddwaf_object *ddwaf_object_insert_const_key(ddwaf_object *object, const char *key, uint32_t length);
ddwaf_object *ddwaf_object_insert_key_nocopy(ddwaf_object *object, char *key, uint32_t length);

// Getters
ddwaf_object_type ddwaf_object_get_type(const ddwaf_object *object);
bool ddwaf_object_get_bool(const ddwaf_object *object);
int64_t ddwaf_object_get_signed(const ddwaf_object *object);
uint64_t ddwaf_object_get_unsigned(const ddwaf_object *object);
double ddwaf_object_get_float(const ddwaf_object *object);

const char *ddwaf_object_get_string(const ddwaf_object *object);
uint32_t ddwaf_object_get_length(const ddwaf_object *object);

uint16_t ddwaf_object_get_size(const ddwaf_object *object);
uint16_t ddwaf_object_get_capacity(const ddwaf_object *object);

// Container accessors
const ddwaf_object *ddwaf_object_get_index(
    const ddwaf_object *object, uint32_t index, const ddwaf_object **key);
const ddwaf_object *ddwaf_object_find_key(
    const ddwaf_object *object, const char *key, uint32_t length);

// Type checkers
bool ddwaf_object_is_invalid(const ddwaf_object *object);
bool ddwaf_object_is_null(const ddwaf_object *object);
bool ddwaf_object_is_bool(const ddwaf_object *object);
bool ddwaf_object_is_signed(const ddwaf_object *object);
bool ddwaf_object_is_unsigned(const ddwaf_object *object);
bool ddwaf_object_is_float(const ddwaf_object *object);
bool ddwaf_object_is_string(const ddwaf_object *object);
bool ddwaf_object_is_array(const ddwaf_object *object);
bool ddwaf_object_is_map(const ddwaf_object *object);
bool ddwaf_object_is_container(const ddwaf_object *object);

#ifdef __cplusplus
}
#endif

#endif // DDWAF_OBJECT_H
