// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <span>
#include <string>

#include "ddwaf.h"
#include "exclusion/common.hpp"

// Internals
// clang-format off
#define PWI_DATA_TYPES (DDWAF_OBJ_SIGNED | DDWAF_OBJ_UNSIGNED | DDWAF_OBJ_STRING | DDWAF_OBJ_BOOL | DDWAF_OBJ_FLOAT)
#define PWI_CONTAINER_TYPES (DDWAF_OBJ_ARRAY | DDWAF_OBJ_MAP)
#define DDWAF_RESULT_INITIALISER {false,  {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_ARRAY}, {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_MAP}, {nullptr, 0, {nullptr}, 0, DDWAF_OBJ_MAP}, 0}
// clang-format on

namespace ddwaf::object {

inline bool is_container(const ddwaf_object *obj)
{
    return obj != nullptr && (obj->type & PWI_CONTAINER_TYPES) != 0 && obj->array != nullptr;
}

inline bool is_map(const ddwaf_object *obj)
{
    return obj != nullptr && obj->type == DDWAF_OBJ_MAP && obj->array != nullptr;
}

inline bool is_scalar(const ddwaf_object *obj)
{
    return obj != nullptr && (obj->type & PWI_DATA_TYPES) != 0;
}

inline bool is_invalid_or_null(const ddwaf_object *obj)
{
    return obj != nullptr && (obj->type == DDWAF_OBJ_INVALID || obj->type == DDWAF_OBJ_NULL);
}

ddwaf_object clone(const ddwaf_object *input);

const ddwaf_object *find_key(
    const ddwaf_object &parent, std::string_view key, const object_limits &limits);

const ddwaf_object *find_key_path(const ddwaf_object *root, std::span<const std::string> key_path,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits);

// Assign source to dest without leaking keys
void assign(ddwaf_object &dest, const ddwaf_object &source);

} // namespace ddwaf::object
