// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "ddwaf.h"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "utils.hpp"

namespace ddwaf::object {

template <typename T>
iterator_base<T>::iterator_base(
    const exclusion::object_set_ref &exclude, const object_limits &limits)
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
template <typename T> std::vector<std::string> iterator_base<T>::get_current_path() const
{
    if (current_ == nullptr) {
        return {};
    }

    std::vector<std::string> keys;
    keys.reserve(path_.size() + stack_.size());
    for (const auto &key : path_) { keys.emplace_back(key); }

    if (stack_.empty()) {
        if (keys.empty()) {
            return {};
        }
        return keys;
    }

    auto [parent, parent_index] = stack_.front();
    for (unsigned i = 1; i < stack_.size(); i++) {
        auto [child, child_index] = stack_[i];
        if (parent->type == DDWAF_OBJ_MAP && child->parameterName != nullptr) {
            keys.emplace_back(child->parameterName, child->parameterNameLength);
        } else if (parent->type == DDWAF_OBJ_ARRAY) {
            keys.emplace_back(to_string<std::string>(parent_index - 1));
        }

        parent = child;
        parent_index = child_index;
    }

    if (parent->type == DDWAF_OBJ_MAP && current_->parameterName != nullptr) {
        keys.emplace_back(current_->parameterName, current_->parameterNameLength);
    } else if (parent->type == DDWAF_OBJ_ARRAY) {
        keys.emplace_back(to_string<std::string>(parent_index - 1));
    }

    return keys;
}

value_iterator::value_iterator(const ddwaf_object *obj, const std::span<const std::string> &path,
    const exclusion::object_set_ref &exclude, const object_limits &limits)
    : iterator_base(exclude, limits)
{
    initialise_cursor(obj, path);
}

void value_iterator::initialise_cursor(
    const ddwaf_object *obj, const std::span<const std::string> &path)
{
    if (excluded_.contains(obj)) {
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
    const ddwaf_object *obj, const std::span<const std::string> &path)
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

                if (excluded_.contains(possible_child)) {
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

        // If null or invalid, we ignore it
        break;
    }

    // Once we reach this point, if current_is valid, we found the key path
    if (current_ != nullptr) {
        for (const auto &p : path) { path_.emplace_back(p); }
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

        if (excluded_.contains(&parent->array[index])) {
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

key_iterator::key_iterator(const ddwaf_object *obj, const std::span<const std::string> &path,
    const exclusion::object_set_ref &exclude, const object_limits &limits)
    : iterator_base(exclude, limits)
{
    initialise_cursor(obj, path);
}

void key_iterator::initialise_cursor(
    const ddwaf_object *obj, const std::span<const std::string> &path)
{
    if (excluded_.contains(obj)) {
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
    const ddwaf_object *obj, const std::span<const std::string> &path)
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

                if (excluded_.contains(possible_child)) {
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
        for (const auto &p : path) { path_.emplace_back(p); }
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

        if (excluded_.contains(child)) {
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

kv_iterator::kv_iterator(const ddwaf_object *obj, const std::span<const std::string> &path,
    const exclusion::object_set_ref &exclude, const object_limits &limits)
    : iterator_base(exclude, limits)
{
    initialise_cursor(obj, path);
}

void kv_iterator::initialise_cursor(
    const ddwaf_object *obj, const std::span<const std::string> &path)
{
    if (excluded_.contains(obj)) {
        return;
    }

    if (path.empty()) {
        if (is_scalar(obj)) {
            current_ = obj;
            scalar_value_ = true;
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

void kv_iterator::initialise_cursor_with_path(
    const ddwaf_object *obj, const std::span<const std::string> &path)
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

                if (excluded_.contains(possible_child)) {
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

        // If we find a scalar and it's the last element,
        // we found a valid element within the path.
        if (is_scalar(child) && (i + 1) == path.size()) {
            current_ = child;
            scalar_value_ = true;
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

    // Once we reach this point, if current_ is valid, we found the key path
    if (current_ != nullptr) {
        for (const auto &p : path) { path_.emplace_back(p); }
    }
}

void kv_iterator::set_cursor_to_next_object()
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

        if (excluded_.contains(child)) {
            ++index;
            continue;
        }

        if (is_container(child)) {
            if (previous != child && child->parameterName != nullptr) {
                current_ = child;
                scalar_value_ = false;
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
        } else if (is_scalar(child)) {
            if (previous != child) {
                current_ = child;
                if (current_->parameterName == nullptr) {
                    ++index;
                    scalar_value_ = true;
                } else {
                    scalar_value_ = false;
                }
                break;
            }

            if (!scalar_value_) {
                current_ = child;
                scalar_value_ = true;
                break;
            }
        } else if (child->parameterName != nullptr) {
            current_ = child;
            scalar_value_ = false;
        }

        ++index;
    }
}
template class iterator_base<value_iterator>;
template class iterator_base<key_iterator>;
template class iterator_base<kv_iterator>;

} // namespace ddwaf::object
