// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "shi_common.hpp"
#include "object_view.hpp"
#include <algorithm>
#include <cstddef>
#include <string_view>
#include <utility>

using namespace std::literals;

namespace ddwaf {

shell_argument_array::shell_argument_array(object_view root)
{
    // Since the type check is performed elsewhere, we don't need to check again
    auto argc = root.size();
    if (argc == 0) {
        return;
    }

    // Calculate the final resource length
    std::size_t resource_len = 0;
    for (std::size_t i = 0; i < argc; ++i) {
        const auto &child = root.at_value(i);
        if (child.is_string() && !child.empty()) {
            // if the string is valid or non-empty, increase the resource
            // length + 1 for the extra space when relevant
            resource_len += child.size() + static_cast<std::size_t>(i > 0);
        }
    }

    indices.reserve(argc);
    resource.reserve(resource_len);

    std::size_t index = 0;
    for (std::size_t i = 0; i < argc; ++i) {
        const auto &child = root.at_value(i);
        if (!child.is_string() || child.empty()) {
            continue;
        }

        const auto str = child.as<std::string_view>();

        indices.emplace_back(index, index + str.size() - 1);

        index += str.size() + 1;

        if (!resource.empty()) {
            resource.append(" "sv);
        }
        resource.append(str);
    }
}

std::size_t shell_argument_array::find(std::string_view str, std::size_t start)
{
    while ((start = resource.find(str, start)) != npos) {
        auto end = start + str.size() - 1;
        // Lower bound returns the first element where the condition is false,
        // which must be equivalent to cur < start_pair for the binary search to
        // work as expected. The condition will match the first iterator where
        // cur.second >= start.
        auto res = std::lower_bound(indices.begin(), indices.end(), std::pair{start, 0},
            [](const auto &cur, const auto &start_pair) { return cur.second < start_pair.first; });

        if (res != indices.end() && res->first <= start && res->second >= end) {
            return start;
        }
        // Otherwise, there's overlap and it's not a valid match.

        // Attempt the next match
        start += 1;
    }
    return npos;
}

} // namespace ddwaf
