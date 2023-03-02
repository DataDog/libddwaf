// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <ddwaf.h>
#include <iterator.hpp>
#include <log.hpp>
#include <utils.hpp>
#include <vector>

namespace ddwaf::object {

template <typename T>
iterator_base<T>::iterator_base(
    const std::pmr::unordered_set<const ddwaf_object *> &exclude, const object_limits &limits)
    : limits_(limits), excluded_(exclude)
{
    stack_.reserve(initial_stack_size);
}

template <typename T> bool iterator_base<T>::operator++()
{
    if (current_ != nullptr) {
        T &derived = static_cast<T &>(*this);
        derived.set_cursor_to_next_object();
    }
    return current_ != nullptr;
}

// TODO: return string_view as this will be immediately copied after
template <typename T> std::pmr::vector<std::pmr::string> iterator_base<T>::get_current_path() const
{
    if (current_ == nullptr) {
        return {};
    }
    if (stack_.empty()) {
        if (path_.empty()) {
            return {};
        }
        return {path_.cbegin(), path_.cend(), excluded_.get_allocator()};
    }

    std::pmr::vector<std::pmr::string> keys{excluded_.get_allocator()};
    keys.reserve(path_.size() + stack_.size());
    keys.insert(keys.begin(), path_.cbegin(), path_.cend());

    auto [parent, parent_index] = stack_.front();
    for (unsigned i = 1; i < stack_.size(); i++) {
        auto [child, child_index] = stack_[i];
        if (parent->type == DDWAF_OBJ_MAP && child->parameterName != nullptr) {
            keys.emplace_back(child->parameterName, child->parameterNameLength);
        } else if (parent->type == DDWAF_OBJ_ARRAY) {
            keys.emplace_back(std::to_string(parent_index - 1));
        }

        parent = child;
        parent_index = child_index;
    }

    if (parent->type == DDWAF_OBJ_MAP && current_->parameterName != nullptr) {
        keys.emplace_back(current_->parameterName, current_->parameterNameLength);
    } else if (parent->type == DDWAF_OBJ_ARRAY) {
        keys.emplace_back(std::to_string(parent_index - 1));
    }

    return keys;
}

value_iterator::value_iterator(const ddwaf_object *obj, const std::vector<std::string> &path,
    const std::pmr::unordered_set<const ddwaf_object *> &exclude, const object_limits &limits)
    : iterator_base(exclude, limits)
{
    initialise_cursor(obj, path);
}

void value_iterator::initialise_cursor(
    const ddwaf_object *obj, const std::vector<std::string> &path)
{
    if (should_exclude(obj)) {
        return;
    }

    if (path.empty()) {
        if (is_scalar(obj)) {
            current_ = obj;
            return;
        }

        // Uninitialised object...? We should throw an exception at some point
        if (!is_container(obj)) {
            return;
        }

        // Add container to stack and find next scalar
        if (limits_.max_container_depth > 0) {
            stack_.emplace_back(obj, 0);
            set_cursor_to_next_object();
        }
    } else {
        initialise_cursor_with_path(obj, path);
    }
}

void value_iterator::initialise_cursor_with_path(
    const ddwaf_object *obj, const std::vector<std::string> &path)
{
    // An object with a path should always start with a container
    if (!is_container(obj)) {
        return;
    }

    if (path.size() > limits_.max_container_depth) {
        return;
    }

    // Add container to stack and find next scalar within the given path
    stack_.emplace_back(obj, 0);

    for (std::size_t i = 0; i < path.size(); i++) {
        const std::string_view key = path[i];
        auto &[parent, index] = stack_.back();

        ddwaf_object *child = nullptr;
        if (is_map(parent)) {
            auto size = parent->nbEntries > limits_.max_container_size ? limits_.max_container_size
                                                                       : parent->nbEntries;
            for (std::size_t j = 0; j < size; j++) {
                auto *possible_child = &parent->array[j];
                if (possible_child->parameterName == nullptr) {
                    continue;
                }

                if (should_exclude(possible_child)) {
                    continue;
                }

                const std::string_view child_key(
                    possible_child->parameterName, possible_child->parameterNameLength);

                if (child_key == key) {
                    child = possible_child;
                    index = j + 1;
                    break;
                }
            }
        }

        // If we find a scalar and it's the last element,
        // we found a valid element within the path.
        if (is_scalar(child) && (i + 1) == path.size()) {
            current_ = child;
            // We want to keep the stack pointing to the container
            // in the last key of the key path, since the last element
            // of the key path is a scalar, we clear the stack.
            stack_.clear();
        } else if (is_container(child)) {
            if ((i + 1) == limits_.max_container_depth) {
                break;
            }

            // Replace the stack top
            stack_.back() = {child, 0};

            if ((i + 1) < path.size()) {
                continue;
            }
            // If it's the last element in the path, we get the next
            // scalar and exit
            set_cursor_to_next_object();
        }

        break;
    }

    // Once we reach this point, if current_is valid, we found the key path
    if (current_ != nullptr) {
        path_ = path;
    }
}

void value_iterator::set_cursor_to_next_object()
{
    current_ = nullptr;

    while (!stack_.empty() && current_ == nullptr) {
        auto &[parent, index] = stack_.back();

        if (index >= parent->nbEntries || index >= limits_.max_container_size) {
            // Pop can invalidate the parent references so after this point
            // they should not be used.
            stack_.pop_back();
            continue;
        }

        if (should_exclude(&parent->array[index])) {
            ++index;
            continue;
        }

        if (is_container(&parent->array[index])) {
            if (depth() < limits_.max_container_depth) {
                // Push can invalidate the current references to the parent
                // so we increment the index before a potential reallocation
                // and prevent any further use of the references.
                stack_.emplace_back(&parent->array[index++], 0);
                continue;
            }
        } else if (is_scalar(&parent->array[index])) {
            current_ = &parent->array[index];
        }

        ++index;
    }
}

key_iterator::key_iterator(const ddwaf_object *obj, const std::vector<std::string> &path,
    const std::pmr::unordered_set<const ddwaf_object *> &exclude, const object_limits &limits)
    : iterator_base(exclude, limits)
{
    initialise_cursor(obj, path);
}

void key_iterator::initialise_cursor(const ddwaf_object *obj, const std::vector<std::string> &path)
{
    if (should_exclude(obj)) {
        return;
    }

    if (!is_container(obj)) {
        return;
    }

    if (path.empty()) {
        // Add container to stack and find next scalar
        if (limits_.max_container_depth > 0) {
            stack_.emplace_back(obj, 0);
            set_cursor_to_next_object();
        }
    } else {
        initialise_cursor_with_path(obj, path);
    }
}

void key_iterator::initialise_cursor_with_path(
    const ddwaf_object *obj, const std::vector<std::string> &path)
{
    if (path.size() >= limits_.max_container_depth) {
        return;
    }

    // Add container to stack and find next scalar within the given path
    stack_.emplace_back(obj, 0);

    for (std::size_t i = 0; i < path.size(); i++) {
        const std::string_view key = path[i];
        auto &[parent, index] = stack_.back();

        ddwaf_object *child = nullptr;
        if (parent->type == DDWAF_OBJ_MAP) {
            auto size = parent->nbEntries > limits_.max_container_size ? limits_.max_container_size
                                                                       : parent->nbEntries;
            for (std::size_t j = 0; j < size; j++) {
                auto *possible_child = &parent->array[j];
                if (possible_child->parameterName == nullptr) {
                    continue;
                }

                if (should_exclude(possible_child)) {
                    continue;
                }

                const std::string_view child_key(
                    possible_child->parameterName, possible_child->parameterNameLength);

                if (child_key == key) {
                    child = possible_child;
                    index = j;
                    break;
                }
            }
        }

        if (is_container(child)) {
            stack_.back() = {child, 0};

            if ((i + 1) < path.size()) {
                continue;
            }

            set_cursor_to_next_object();
        }

        break;
    }

    // Once we reach this point, if current_ is valid, we found the key path
    if (current_ != nullptr) {
        path_ = path;
    }
}

void key_iterator::set_cursor_to_next_object()
{
    const ddwaf_object *previous = current_;
    current_ = nullptr;

    while (!stack_.empty() && current_ == nullptr) {
        auto &[parent, index] = stack_.back();

        if (index >= parent->nbEntries || index >= limits_.max_container_size) {
            // Pop can invalidate the parent references so after this point
            // they should not be used.
            stack_.pop_back();
            continue;
        }

        ddwaf_object *child = &parent->array[index];

        if (should_exclude(child)) {
            ++index;
            continue;
        }

        if (is_container(child)) {
            if (previous != child && child->parameterName != nullptr) {
                current_ = child;
                // Break to ensure the index isn't increased and this container
                // is fully iterated.
                break;
            }

            if (depth() < limits_.max_container_depth) {
                // Push can invalidate the current references to the parent
                // so we increment the index before a potential reallocation
                // and prevent any further use of the references.
                ++index;
                stack_.emplace_back(child, 0);
                continue;
            }
        } else if (child->parameterName != nullptr) {
            current_ = child;
        }

        ++index;
    }
}

template class iterator_base<value_iterator>;
template class iterator_base<key_iterator>;

} // namespace ddwaf::object
