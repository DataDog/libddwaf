// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer_cache.hpp"
#include "log.hpp"

namespace ddwaf {

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
        ddwaf_object_stringl(&copy, previous->stringValue, length);

        if (!PWTransformer::transform(transformer, &copy)) {
            // Transform failed, let's skip it and continue
            ddwaf_object_free(&copy);
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

} // namespace ddwaf
