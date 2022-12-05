// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <exclusion/object_filter.hpp>
#include <log.hpp>

namespace ddwaf::exclusion {

path_trie path_trie::find(std::string_view key) const
{
    if (!root) {
        return {};
    }
    auto it = root->values.find(key);
    if (it == root->values.end()) {
        return {};
    }
    return path_trie{it->second};
}

template <typename T> path_trie path_trie::find(const std::vector<T> &path) const
{
    if (!root) {
        return {};
    }

    std::shared_ptr<trie_node> current = root;
    for (const auto &key : path) {
        auto it = current->values.find(key);
        if (it == current->values.end()) {
            return {};
        }
        current = it->second;
    }
    return path_trie{current};
}

std::string_view path_trie::get_stored_string(std::string_view str)
{
    auto it = string_store.find(str);
    if (it == string_store.end()) {
        auto [new_it, res] = string_store.emplace(str);
        return *new_it;
    }
    return *it;
}

template <typename T> void path_trie::insert(const std::vector<T> &path)
{
    if (!root) {
        root = std::make_shared<trie_node>();
    }

    std::shared_ptr<trie_node> current = root;
    for (const auto &key : path) {
        // If the current node is terminal, the given path is already
        // partially or totally in the trie.
        if (current->terminal) {
            break;
        }

        auto it = current->values.find(key);
        if (it == current->values.end()) {
            auto stored_key = get_stored_string(key);
            const auto &[new_it, res] =
                current->values.emplace(stored_key, std::make_shared<trie_node>());
            current = new_it->second;

        } else {
            current = it->second;
        }
    }
    current->terminal = true;
}

// Instantiations
template path_trie path_trie::find<std::string>(const std::vector<std::string> &path) const;
template void path_trie::insert<std::string>(const std::vector<std::string> &path);
template path_trie path_trie::find<std::string_view>(
    const std::vector<std::string_view> &path) const;
template void path_trie::insert<std::string_view>(const std::vector<std::string_view> &path);

namespace {
void iterate_object(const path_trie &filter, const ddwaf_object *object,
    std::unordered_set<const ddwaf_object *> &objects_to_exclude, const object_limits &limits)
{
    if (object == nullptr) {
        return;
    }

    if (filter.is_terminal()) {
        objects_to_exclude.emplace(object);
        return;
    }

    if (object->type != DDWAF_OBJ_MAP) {
        return;
    }
    std::stack<std::tuple<const ddwaf_object *, unsigned, path_trie>> path_stack;
    path_stack.push({object, 0, filter});

    while (!path_stack.empty()) {
        auto &[current_object, current_index, current_trie] = path_stack.top();
        if (current_object->type != DDWAF_OBJ_MAP) {
            DDWAF_DEBUG("This is a bug, the object in the stack is not a map");
            path_stack.pop();
            continue;
        }

        bool found_node{false};
        auto size = current_object->nbEntries > limits.max_container_size
                        ? limits.max_container_size
                        : current_object->nbEntries;
        for (; current_index < size; ++current_index) {
            ddwaf_object *child = &current_object->array[current_index];

            // Only consider children with keys
            if (child->parameterName == nullptr || child->parameterNameLength == 0) {
                continue;
            }

            std::string_view key{
                child->parameterName, static_cast<std::size_t>(child->parameterNameLength)};
            auto child_trie = current_trie.find(key);

            if (child_trie.is_terminal()) {
                objects_to_exclude.emplace(child);
                continue;
            }

            if (child->type == DDWAF_OBJ_MAP && child_trie.is_valid() &&
                path_stack.size() < limits.max_container_depth) {
                ++current_index;
                found_node = true;
                path_stack.push({child, 0, child_trie});
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
        iterate_object(filter, object, objects_to_exclude, limits_);

        cache.emplace(target);
    }

    return objects_to_exclude;
}

} // namespace ddwaf::exclusion
