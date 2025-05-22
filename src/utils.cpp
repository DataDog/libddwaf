// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <cstdint>
#include <list>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "ddwaf.h"
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

// This could eventually be delegated to the argument retriever, albeit it would
// need to be refactored to allow for key path retrieval or not
const ddwaf_object *find_key_path(const ddwaf_object &root, std::span<const std::string> key_path)
{
    const auto *current = &root;
    for (auto it = key_path.begin(); current != nullptr && it != key_path.end(); ++it) {
        const auto &root = *current;
        if (root.type != DDWAF_OBJ_MAP) {
            return nullptr;
        }

        // Reset to search for next object in the path
        current = nullptr;
        for (std::size_t i = 0; i < static_cast<uint32_t>(root.nbEntries); ++i) {
            const auto &child = root.array[i];

            if (child.parameterName == nullptr) [[unlikely]] {
                continue;
            }
            const std::string_view child_key{
                child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};

            if (*it == child_key) {
                current = &child;
                break;
            }
        }
    }
    return current;
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
