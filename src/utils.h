// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <optional>
#include <stdint.h>

// IP Utils
typedef struct
{
    uint8_t ip[16]; // big endian
    bool isIPv6;
} parsed_ip;

template <typename T>
using optional_ref = std::optional<std::reference_wrapper<T>>;

size_t find_string_cutoff(const char *str, size_t length,
        uint32_t max_string_length = DDWAF_MAX_STRING_LENGTH);

//Internals
#define IS_CONTAINER(obj) ((obj)->type & (DDWAF_OBJ_ARRAY | DDWAF_OBJ_MAP))

#define PWI_DATA_TYPES (DDWAF_OBJ_SIGNED | DDWAF_OBJ_UNSIGNED | DDWAF_OBJ_STRING)
#define PWI_CONTAINER_TYPES (DDWAF_OBJ_ARRAY | DDWAF_OBJ_MAP)