// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "transformer_cache.hpp"
#include "log.hpp"

namespace ddwaf {

const ddwaf_object* transformer_cache::transform(const ddwaf_object *source, size_t length, const std::vector<PW_TRANSFORM_ID> &transformers)
{
    if (source == nullptr || transformers.empty()) {
        return nullptr;
    }

    if (!requires_transform(source, length, transformers)) {
        return nullptr;
    }

    const ddwaf_object *previous = source;
    for (auto transformer : transformers) {
        auto it = transform_cache_.find({previous, transformer});
        if (it != transform_cache_.end()) {
            previous = it->second;
            continue;
        }

        ddwaf_object copy;
        ddwaf_object_stringl(&copy, previous->stringValue, length);

        if (!PWTransformer::transform(transformer, &copy)) {
            ddwaf_object_free(&copy);
            return nullptr;
        }

        // Add to the owned_objects_, get the point and also add it to the cache
        owned_objects_.emplace_front(copy);
        auto *current = &owned_objects_.front();

        cache_key key{previous, transformer};
        transform_cache_.emplace(key, current);

        previous = current;

        if (previous->type == DDWAF_OBJ_STRING && previous->nbEntries == 0) {
            // No point in continuing the transform
            break;
        }

        length = previous->nbEntries;
    }

    return previous;
}

bool transformer_cache::requires_transform(const ddwaf_object *source, size_t length, const std::vector<PW_TRANSFORM_ID> &transformers)
{
    // TODO cache this as well?
    ddwaf_object data = *source;
    data.nbEntries = length;

    for (auto id : transformers) {
        if (PWTransformer::transform(id, &data, true)) {
            return true;
        }
    }

    return false;
}

} // namespace ddwaf
