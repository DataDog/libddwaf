// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <exclusion/object_filter.hpp>
#include <log.hpp>
#include <utils.h>

namespace ddwaf::exclusion {

namespace {
void iterate_object(const path_trie::traverser &filter, const ddwaf_object *object,
    std::unordered_set<const ddwaf_object *> &objects_to_exclude, const object_limits &limits)
{
    using state = path_trie::traverser::state;
    if (object == nullptr) {
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

    if (!object::is_container(object)) {
        return;
    }

    std::stack<std::tuple<const ddwaf_object *, unsigned, path_trie::traverser>> path_stack;
    path_stack.push({object, 0, filter});

    while (!path_stack.empty()) {
        auto &[current_object, current_index, current_trie] = path_stack.top();
        if (!object::is_container(current_object)) {
            DDWAF_DEBUG("This is a bug, the object in the stack is not a container");
            path_stack.pop();
            continue;
        }

        bool found_node{false};
        auto size = current_object->nbEntries > limits.max_container_size
                        ? limits.max_container_size
                        : current_object->nbEntries;
        for (; current_index < size; ++current_index) {
            ddwaf_object *child = &current_object->array[current_index];

            path_trie::traverser child_traverser{nullptr};
            // Only consider children with keys
            if (child->parameterName == nullptr || child->parameterNameLength == 0) {
                child_traverser = current_trie.descend_wildcard();
            } else {
                std::string_view key{
                    child->parameterName, static_cast<std::size_t>(child->parameterNameLength)};
                child_traverser = current_trie.descend(key);
            }
            const auto filter_state = child_traverser.get_state();

            if (filter_state == state::found) {
                objects_to_exclude.emplace(child);
                continue;
            }
            if (filter_state == state::not_found) {
                continue;
            }

            if (object::is_container(child) && path_stack.size() < limits.max_container_depth) {
                ++current_index;
                found_node = true;
                path_stack.push({child, 0, child_traverser});
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

std::unordered_set<const ddwaf_object *> object_filter::match(
    const object_store &store, cache_type &cache, ddwaf::timer &deadline) const
{
    std::unordered_set<const ddwaf_object *> objects_to_exclude;
    for (const auto &[target, filter] : target_paths_) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (cache.find(target) != cache.end()) {
            continue;
        }

        const auto *object = store.get_target(target);
        if (object == nullptr) {
            continue;
        }
        iterate_object(filter.get_traverser(), object, objects_to_exclude, limits_);

        cache.emplace(target);
    }

    return objects_to_exclude;
}

} // namespace ddwaf::exclusion
