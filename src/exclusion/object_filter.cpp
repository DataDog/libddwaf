// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <stack>
#include <string_view>
#include <tuple>
#include <unordered_set>

#include "clock.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "exclusion/object_filter.hpp"
#include "log.hpp"
#include "object.hpp"
#include "object_store.hpp"

namespace ddwaf::exclusion {

namespace {
// Add requires
void iterate_object(const path_trie::traverser &filter, object_view object,
    std::unordered_set<object_view> &objects_to_exclude)
{
    using state = path_trie::traverser::state;
    if (!object.has_value()) {
        return;
    }

    {
        const auto filter_state = filter.get_state();
        if (filter_state == state::not_found) {
            return;
        }
        if (filter_state == state::found) {
            objects_to_exclude.emplace(object);
            return;
        }
    }

    if (!object.is_container()) {
        return;
    }

    std::stack<std::tuple<object_view, unsigned, path_trie::traverser>> path_stack;
    path_stack.emplace(object, 0, filter);

    while (!path_stack.empty()) {
        auto &[current_object, current_index, current_trie] = path_stack.top();
        if (!object.is_container()) {
            DDWAF_DEBUG("This is a bug, the object in the stack is not a container");
            path_stack.pop();
            continue;
        }

        bool found_node{false};
        for (; current_index < current_object.size(); ++current_index) {
            auto [key, child] = current_object.at(current_index);

            path_trie::traverser child_traverser{nullptr};
            // Only consider children with keys
            if (key.empty()) {
                child_traverser = current_trie.descend_wildcard();
            } else {
                child_traverser = current_trie.descend(key.as<std::string_view>());
            }
            const auto filter_state = child_traverser.get_state();

            if (filter_state == state::found) {
                objects_to_exclude.emplace(child);
                continue;
            }
            if (filter_state == state::not_found) {
                continue;
            }

            if (child.is_container()) {
                ++current_index;
                found_node = true;
                path_stack.emplace(child, 0, child_traverser);
                break;
            }
        }

        if (!found_node) {
            // We reached the end of the container, so we pop it and continue
            // iterating the parent.
            // Note that this invalidates all references to top()
            path_stack.pop();
        }
    }
}

} // namespace

object_set object_filter::match(
    const object_store &store, cache_type &cache, bool ephemeral, ddwaf::timer &deadline) const
{
    object_set objects_to_exclude;
    for (const auto &[target, filter] : target_paths_) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        auto [object, attr] = store.get_target(target);
        if (!object.has_value() || cache.contains(object)) {
            continue;
        }

        if (!ephemeral && attr != object_store::attribute::ephemeral) {
            cache.emplace(object);
            iterate_object(filter.get_traverser(), object, objects_to_exclude.persistent);
        } else {
            iterate_object(filter.get_traverser(), object, objects_to_exclude.ephemeral);
        }
    }

    return objects_to_exclude;
}

} // namespace ddwaf::exclusion
