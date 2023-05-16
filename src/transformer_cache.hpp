// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "config.hpp"
#include "ddwaf.h"

#include "PWTransformer.h"

#include <array>
#include <list>
#include <unordered_map>

namespace ddwaf {

class transformer_cache {
public:
    transformer_cache() = default;
    transformer_cache(const transformer_cache &) = delete;
    transformer_cache(transformer_cache &&) = delete;
    transformer_cache& operator=(const transformer_cache &) = delete;
    transformer_cache& operator=(transformer_cache &&) = delete;

    ~transformer_cache() {
        for (auto object : owned_objects_) {
            ddwaf_object_free(&object);
        }
    }

    const ddwaf_object* transform(const ddwaf_object *source, size_t length, const std::vector<PW_TRANSFORM_ID> &transformers);
protected:
    static bool requires_transform(const ddwaf_object *source, size_t length, const std::vector<PW_TRANSFORM_ID> &transformers);

    std::list<ddwaf_object> owned_objects_{};
    ddwaf::object_limits limits_{};

    using cache_key = std::pair<const ddwaf_object *, PW_TRANSFORM_ID>;
    struct cash_key_hash {
        std::size_t operator()(const cache_key &s) const noexcept
        {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast, cppcoreguidelines-pro-type-reinterpret-cast)
            void *ptr = reinterpret_cast<void*>(const_cast<ddwaf_object *>(s.first));
            return std::hash<void *>{}(ptr) ^ std::hash<PW_TRANSFORM_ID>{}(s.second);
        }
    };

    std::unordered_map<cache_key, const ddwaf_object *, cash_key_hash> transform_cache_{};
};

} // namespace ddwaf
