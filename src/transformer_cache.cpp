// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer_cache.hpp"
#include "log.hpp"

namespace ddwaf {

namespace {
void copy_string_object(ddwaf_object &destination, const ddwaf_object &source, size_t length)
{
    memory::context_allocator<char> alloc;

    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    char *copy = alloc.allocate(length + 1);

    memcpy(copy, source.stringValue, length);
    copy[length] = '\0';

    destination = {nullptr, 0, {copy}, length, DDWAF_OBJ_STRING};
}

void free_string_object(ddwaf_object &object)
{
    memory::context_allocator<char> alloc;
    // NOLINTNEXTLINE
    alloc.deallocate(const_cast<char *>(object.stringValue), object.nbEntries + 1);
}

} // namespace
std::pair<const ddwaf_object *, bool> transformer_cache::transform(
    const ddwaf_object *source, size_t length, const std::vector<PW_TRANSFORM_ID> &transformers)
{
    if (source == nullptr || transformers.empty()) {
        return {nullptr, false};
    }

    const ddwaf_object *previous = source;
    for (auto transformer : transformers) {
        auto it = transform_cache_.find({previous, transformer});
        if (it != transform_cache_.end()) {
            previous = it->second;
            if (previous->type == DDWAF_OBJ_STRING && previous->nbEntries == 0) {
                // No point in continuing the transform
                break;
            }
            length = previous->nbEntries;
            continue;
        }

        cache_key key{previous, transformer};

        // NOLINTNEXTLINE
        if (!PWTransformer::transform(transformer, const_cast<ddwaf_object *>(previous), true)) {
            transform_cache_.emplace(key, previous);
            continue;
        }

        ddwaf_object copy;
        copy_string_object(copy, *previous, length);

        if (!PWTransformer::transform(transformer, &copy)) {
            // Transform failed, let's skip it and continue
            free_string_object(copy);
            transform_cache_.emplace(key, previous);
            continue;
        }

        // Add to the owned_objects_, get the point and also add it to the cache
        owned_objects_.emplace_front(copy);
        auto *current = &owned_objects_.front();

        transform_cache_.emplace(key, current);

        previous = current;
        if (previous->type == DDWAF_OBJ_STRING && previous->nbEntries == 0) {
            // No point in continuing the transform
            break;
        }

        length = previous->nbEntries;
    }

    return {previous, true};
}

transformer_cache::~transformer_cache()
{
    for (auto object : owned_objects_) { free_string_object(object); }
}

} // namespace ddwaf
