// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exclusion_filter.hpp>

namespace ddwaf {

exclusion_filter::index_type global_index_ = 0;

bool exclusion_filter::match(const object_store& store,
    const ddwaf::manifest &manifest, ddwaf::timer& deadline) const
{
    for (const ddwaf::condition& cond : conditions_) {
        auto opt_match = cond.match(store, manifest, true, deadline);
        if (!opt_match.has_value()) {
            return false;
        }
    }

    return true;
}

} // namespace ddwaf
