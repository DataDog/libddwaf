// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <list>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "ddwaf.h"
#include "exclusion/common.hpp"
#include "object_helpers.hpp"
#include "utils.hpp"

namespace ddwaf::object {

namespace {

void clone_helper(const ddwaf_object &source, ddwaf_object &destination)
{
    switch (source.type) {
    case DDWAF_OBJ_BOOL:
        ddwaf_object_bool(&destination, source.boolean);
        break;
    case DDWAF_OBJ_STRING:
        ddwaf_object_stringl(&destination, source.stringValue, source.nbEntries);
        break;
    case DDWAF_OBJ_SIGNED:
        ddwaf_object_signed(&destination, source.intValue);
        break;
    case DDWAF_OBJ_UNSIGNED:
        ddwaf_object_unsigned(&destination, source.uintValue);
        break;
    case DDWAF_OBJ_FLOAT:
        ddwaf_object_float(&destination, source.f64);
        break;
    case DDWAF_OBJ_INVALID:
        ddwaf_object_invalid(&destination);
        break;
    case DDWAF_OBJ_NULL:
        ddwaf_object_null(&destination);
        break;
    case DDWAF_OBJ_MAP:
        ddwaf_object_map(&destination);
        break;
    case DDWAF_OBJ_ARRAY:
        ddwaf_object_array(&destination);
        break;
    }
}

} // namespace

ddwaf_object clone(const ddwaf_object *input)
{
    ddwaf_object tmp;
    ddwaf_object_invalid(&tmp);

    ddwaf_object copy;
    std::list<std::pair<const ddwaf_object *, ddwaf_object *>> queue;

    clone_helper(*input, copy);
    if (is_container(input)) {
        queue.emplace_front(input, &copy);
    }

    while (!queue.empty()) {
        auto [source, destination] = queue.front();
        for (uint64_t i = 0; i < source->nbEntries; ++i) {
            const auto &child = source->array[i];
            clone_helper(child, tmp);
            if (source->type == DDWAF_OBJ_MAP) {
                ddwaf_object_map_addl(
                    destination, child.parameterName, child.parameterNameLength, &tmp);
            } else if (source->type == DDWAF_OBJ_ARRAY) {
                ddwaf_object_array_add(destination, &tmp);
            }
        }

        for (uint64_t i = 0; i < source->nbEntries; ++i) {
            if (is_container(&source->array[i])) {
                queue.emplace_back(&source->array[i], &destination->array[i]);
            }
        }

        queue.pop_front();
    }

    return copy;
}

const ddwaf_object *find_key(
    const ddwaf_object &parent, std::string_view key, const object_limits &limits)
{
    const std::size_t size =
        std::min(static_cast<uint32_t>(parent.nbEntries), limits.max_container_size);
    for (std::size_t i = 0; i < size; ++i) {
        const auto &child = parent.array[i];

        if (child.parameterName == nullptr) [[unlikely]] {
            continue;
        }
        const std::string_view child_key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};

        if (key == child_key) {
            return &child;
        }
    }

    return nullptr;
}

const ddwaf_object *find_key_path(const ddwaf_object *root, std::span<const std::string> key_path,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits)
{
    if (objects_excluded.contains(root)) {
        return nullptr;
    }

    if (key_path.empty()) {
        return root;
    }

    if (root->type == DDWAF_OBJ_MAP) {
        auto it = key_path.begin();
        while ((root = find_key(*root, *it, limits)) != nullptr) {
            if (objects_excluded.contains(root)) {
                break;
            }

            if (++it == key_path.end()) {
                return root;
            }

            if (root->type != DDWAF_OBJ_MAP) {
                break;
            }
        }
    }

    return nullptr;
}

void assign(ddwaf_object &dest, const ddwaf_object &source)
{
    const auto *parameterName = dest.parameterName;
    auto parameterNameLength = dest.parameterNameLength;

    dest = source;
    dest.parameterName = parameterName;
    dest.parameterNameLength = parameterNameLength;
}

} // namespace ddwaf::object
