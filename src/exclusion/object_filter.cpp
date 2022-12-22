// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <exclusion/object_filter.hpp>
#include <log.hpp>
#include <tuple>
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

    using stack_elem = std::tuple<const ddwaf_object *, path_trie::path*, unsigned, path_trie::traverser>;

    std::stack<stack_elem> path_stack;
    path_stack.emplace(object, nullptr, 0, filter);

    while (!path_stack.empty()) {
        auto &top = path_stack.top();
        const ddwaf_object *current_object = std::get<0>(top);
        path_trie::path *current_path = std::get<1>(top);
        const unsigned current_depth = std::get<2>(top);
        const auto current_trie{std::move(std::get<3>(top))};
        path_stack.pop();

        if (!object::is_container(current_object)) {
            DDWAF_DEBUG("This is a bug, the object in the stack is not a container");
            continue;
        }

        auto size = current_object->nbEntries > limits.max_container_size
                        ? limits.max_container_size
                        : current_object->nbEntries;
        bool first_child = true;
        for (unsigned i = 0; i < size; i++) {
            ddwaf_object *child = &current_object->array[i];

            path_trie::traverser child_traverser{nullptr};
            std::string_view component;
            if (child->parameterName == nullptr || child->parameterNameLength == 0) {
               component = {};
            } else {
                component = {
                    child->parameterName, static_cast<std::size_t>(child->parameterNameLength)};
            }
            auto *p = new path_trie::path(current_path, component);

            child_traverser = current_trie.descend(p);

            const auto filter_state = child_traverser.get_state();

            if (filter_state == state::found) {
                objects_to_exclude.emplace(child);
                delete p;
            } else if (filter_state == state::not_found) {
                delete p;
            } else if (object::is_container(child) && current_depth < limits.max_container_depth) {
                if (first_child) {
                    p->first_child = true;
                    first_child = false;
                } else {
                    p->first_child = false;
                }
                path_stack.push({child, p, i + 1, std::move(child_traverser)});
            }
        }

        bool no_children = first_child;
        if (no_children && current_path != nullptr /* not root node */) {
            // if we have no children, delete our path component
            // and delete also the path component of the parent if
            // we are the first child (and thus the last visited)
            bool cur_first_child{true};
            path_trie::path *prev = current_path;
            do {
                path_trie::path *cur = prev;
                prev = cur->prev;
                cur_first_child = cur->first_child;
                delete cur;
            } while (prev != nullptr && cur_first_child);
        }
    } // while (!path_stack.empty())
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
