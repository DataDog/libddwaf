// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "component_target_index.hpp"
#include "target_address.hpp"

namespace ddwaf {

component_target_index::component_target_index(std::vector<reference> references)
{
    if (references.empty()) {
        return;
    }

    std::sort(references.begin(), references.end(), [](const auto &lhs, const auto &rhs) {
        return lhs.target < rhs.target || (lhs.target == rhs.target && lhs.component < rhs.component);
    });

    ranges_.resize(references.back().target + 1);
    for (std::size_t i = 0; i < references.size();) {
        const auto target = references[i].target;
        const auto begin = sets_.size();
        for (; i < references.size() && references[i].target == target; ++i) {
            const auto component = references[i].component;
            const component_set set{.word = static_cast<uint32_t>(component / word_bits),
                .mask = uint64_t{1} << (component % word_bits)};

            // Components are sorted, so a component can only belong to the
            // last set of the target, if any.
            if (sets_.size() == begin || sets_.back().word != set.word) {
                sets_.emplace_back(set);
            } else {
                sets_.back().mask |= set.mask;
            }
        }
        ranges_[target] = {
            .begin = static_cast<uint32_t>(begin), .end = static_cast<uint32_t>(sets_.size())};
    }
}

} // namespace ddwaf
