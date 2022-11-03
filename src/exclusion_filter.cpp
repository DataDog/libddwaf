// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exclusion_filter.hpp>

namespace ddwaf {

bool exclusion_filter::filter(const object_store& store,
    const ddwaf::manifest &manifest,
    cache_type &cache, ddwaf::timer& deadline) const
{
    for (auto cond : conditions_) {
        // If there's a (false) cache hit, we only need to run this condition
        // on new parameters.
        bool run_on_new = false;
        auto cached_result = cache.find(cond);
        if (cached_result != cache.end()) {
            if (cached_result->second) {
                continue;
            }
            run_on_new = true;
        }

        // TODO: Condition interface without events
        auto opt_match = cond->match(store, manifest, run_on_new, deadline);
        if (!opt_match.has_value()) {
            return false;
        }
    }

    return true;
}

} // namespace ddwaf
