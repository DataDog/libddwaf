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
#include "object_view.hpp"
#include "utils.hpp"

namespace ddwaf {

template <typename T>
iterator_base<T>::iterator_base(
    const exclusion::object_set_ref &exclude, const object_limits &limits)
    : limits_(limits), excluded_(exclude)
{
    stack_.reserve(initial_stack_size);
}

template <typename T> bool iterator_base<T>::operator++()
{
    if (*static_cast<T *>(this)) {
        T &derived = static_cast<T &>(*this);
        derived.set_cursor_to_next_object();
    }
    return static_cast<bool>(*static_cast<T *>(this));
}

// TODO: return string_view as this will be immediately copied after
template <typename T> std::vector<std::string> iterator_base<T>::get_current_path() const
{
    if (!*static_cast<const T *>(this)) {
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

    for (auto it : stack_) {
        // TODO make this return an std::string_view
        detail::object_iterator current = it;
        if (current.index > 0) {
            --current.index;
        }
        if (auto key = current.key(); !key.empty()) {
            keys.emplace_back(key);
        } else {
            // TODO intern these strings or use std::variant in the return
            keys.emplace_back(to_string<std::string>(current.index));
        }
    }

    return keys;
}

value_iterator::value_iterator(object_view obj, std::span<const std::string> path,
    const exclusion::object_set_ref &exclude, const object_limits &limits)
    : iterator_base(exclude, limits)
{
    initialise_cursor(obj, path);
}

void value_iterator::initialise_cursor(object_view obj, std::span<const std::string> path)
{
    if (excluded_.contains(obj.ptr())) {
        return;
    }

    if (path.empty()) {
        if (obj.is_scalar()) {
            current_ = obj.ptr();
            return;
        }

        // Uninitialised object...? We should throw an exception at some point
        if (!obj.is_container()) {
            return;
        }

        // Add container to stack and find next scalar
        if (limits_.max_container_depth > 0) {
            stack_.emplace_back(
                detail::object_iterator::construct(obj.ptr(), 0, limits_.max_container_size));
            set_cursor_to_next_object();
        }
    } else {
        initialise_cursor_with_path(obj, path);
    }
}

void value_iterator::initialise_cursor_with_path(object_view obj, std::span<const std::string> path)
{
    // An object with a path should always start with a container
    if (!obj.is_container()) {
        return;
    }

    if (path.size() > limits_.max_container_depth) {
        return;
    }

    // Add container to stack and find next scalar within the given path
    stack_.emplace_back(
        detail::object_iterator::construct(obj.ptr(), 0, limits_.max_container_size));

    for (std::size_t i = 0; i < path.size(); i++) {
        const std::string_view key = path[i];
        auto &it = stack_.back();

        std::pair<std::string_view, object_view> child;
        for (; it.is_valid(); ++it) {
            std::pair<std::string_view, object_view> possible_child = *it;

            if (excluded_.contains(possible_child.second.ptr())) {
                continue;
            }

            if (possible_child.first == key) {
                child = possible_child;
                ++it;
                break;
            }
        }

        // If we find a scalar and it's the last element,
        // we found a valid element within the path.
        if (child.second.is_scalar() && (i + 1) == path.size()) {
            current_ = child.second.ptr();
            // We want to keep the stack pointing to the container
            // in the last key of the key path, since the last element
            // of the key path is a scalar, we clear the stack.
            stack_.clear();
        } else if (child.second.is_container()) {
            if ((i + 1) == limits_.max_container_depth) {
                break;
            }

            // Replace the stack top
            stack_.back() = detail::object_iterator::construct(
                child.second.ptr(), 0, limits_.max_container_size);

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
        auto &it = stack_.back();

        if (it.index >= it.size) {
            // Pop can invalidate the parent references so after this point
            // they should not be used.
            stack_.pop_back();
            continue;
        }

        const auto *child = it.value();
        if (excluded_.contains(child)) {
            ++it.index;
            continue;
        }

        if (is_container(static_cast<object_type>(child->type))) {
            if (depth() < limits_.max_container_depth) {
                // Push can invalidate the current references to the parent
                // so we increment the index before a potential reallocation
                // and prevent any further use of the references.
                ++it.index;
                stack_.emplace_back(detail::object_iterator{
                    .ptr = child->array,
                    .index = 0,
                    .size = child->nbEntries < limits_.max_container_size
                                ? static_cast<std::size_t>(child->nbEntries)
                                : limits_.max_container_size,
                    .type = child->type,
                });
                continue;
            }
        } else if (is_scalar(static_cast<object_type>(child->type))) {
            current_ = child;
        }

        ++it.index;
    }
}

key_iterator::key_iterator(object_view obj, std::span<const std::string> path,
    const exclusion::object_set_ref &exclude, const object_limits &limits)
    : iterator_base(exclude, limits)
{
    initialise_cursor(obj, path);
}

void key_iterator::initialise_cursor(object_view obj, std::span<const std::string> path)
{
    if (excluded_.contains(obj.ptr())) {
        return;
    }

    if (!obj.is_container()) {
        return;
    }

    if (path.empty()) {
        // Add container to stack and find next scalar
        if (limits_.max_container_depth > 0) {
            stack_.emplace_back(
                detail::object_iterator::construct(obj.ptr(), 0, limits_.max_container_size));
            set_cursor_to_next_object();
        }
    } else {
        initialise_cursor_with_path(obj, path);
    }
}

void key_iterator::initialise_cursor_with_path(object_view obj, std::span<const std::string> path)
{
    if (path.size() >= limits_.max_container_depth) {
        return;
    }

    // Add container to stack and find next scalar within the given path
    stack_.emplace_back(
        detail::object_iterator::construct(obj.ptr(), 0, limits_.max_container_size));

    for (std::size_t i = 0; i < path.size(); i++) {
        const std::string_view key = path[i];
        auto &it = stack_.back();

        std::pair<std::string_view, object_view> child;
        if (static_cast<object_type>(it.type) == object_type::map) {
            for (; it.is_valid(); ++it) {
                std::pair<std::string_view, object_view> possible_child = *it;
                if (possible_child.first.empty()) {
                    continue;
                }

                if (excluded_.contains(possible_child.second.ptr())) {
                    continue;
                }

                if (possible_child.first == key) {
                    child = possible_child;
                    break;
                }
            }
        }

        if (child.second.is_container()) {
            stack_.back() = detail::object_iterator::construct(
                child.second.ptr(), 0, limits_.max_container_size);

            if ((i + 1) < path.size()) {
                continue;
            }

            set_cursor_to_next_object();
        }

        break;
    }

    // Once we reach this point, if current_ is valid, we found the key path
    if (current_.second.has_value()) {
        for (const auto &p : path) { path_.emplace_back(p); }
    }
}

void key_iterator::set_cursor_to_next_object()
{
    auto previous = current_;
    current_ = {};

    while (!stack_.empty() && !current_.second.has_value()) {
        auto &it = stack_.back();

        if (!it.is_valid()) {
            // Pop can invalidate the parent references so after this point
            // they should not be used.
            stack_.pop_back();
            continue;
        }

        std::pair<std::string_view, object_view> child = *it;
        if (excluded_.contains(child.second.ptr())) {
            ++it;
            continue;
        }

        if (child.second.is_container()) {
            if (previous.second != child.second && !child.first.empty()) {
                current_ = {child.first, child.second};
                // Break to ensure the index isn't increased and this container
                // is fully iterated.
                break;
            }

            if (depth() < limits_.max_container_depth) {
                // Push can invalidate the current references to the parent
                // so we increment the index before a potential reallocation
                // and prevent any further use of the references.
                ++it;
                stack_.emplace_back(detail::object_iterator::construct(
                    child.second.ptr(), 0, limits_.max_container_size));
                continue;
            }
        } else if (!child.first.empty()) {
            current_ = {child.first, child.second};
        }

        ++it;
    }
}

kv_iterator::kv_iterator(object_view obj, std::span<const std::string> path,
    const exclusion::object_set_ref &exclude, const object_limits &limits)
    : iterator_base(exclude, limits)
{
    initialise_cursor(obj, path);
}

void kv_iterator::initialise_cursor(object_view obj, std::span<const std::string> path)
{
    if (excluded_.contains(obj.ptr())) {
        return;
    }

    if (path.empty()) {
        if (obj.is_scalar()) {
            current_ = {{}, obj};
            scalar_value_ = true;
            return;
        }

        // Uninitialised object...? We should throw an exception at some point
        if (!obj.is_container()) {
            return;
        }

        // Add container to stack and find next scalar
        if (limits_.max_container_depth > 0) {
            stack_.emplace_back(
                detail::object_iterator::construct(obj.ptr(), 0, limits_.max_container_size));
            set_cursor_to_next_object();
        }
    } else {
        initialise_cursor_with_path(obj, path);
    }
}

void kv_iterator::initialise_cursor_with_path(object_view obj, std::span<const std::string> path)
{
    if (path.size() >= limits_.max_container_depth) {
        return;
    }

    // Add container to stack and find next scalar within the given path
    stack_.emplace_back(
        detail::object_iterator::construct(obj.ptr(), 0, limits_.max_container_size));

    for (std::size_t i = 0; i < path.size(); i++) {
        const std::string_view key = path[i];
        auto &it = stack_.back();

        std::pair<std::string_view, object_view> child;
        if (static_cast<object_type>(it.type) == object_type::map) {
            for (; it.is_valid(); ++it) {
                std::pair<std::string_view, object_view> possible_child = *it;

                if (possible_child.first.empty()) {
                    continue;
                }

                if (excluded_.contains(possible_child.second.ptr())) {
                    continue;
                }

                if (possible_child.first == key) {
                    child = possible_child;
                    break;
                }
            }
        }

        // If we find a scalar and it's the last element,
        // we found a valid element within the path.
        if (child.second.is_scalar() && (i + 1) == path.size()) {
            current_ = child;
            scalar_value_ = true;
            // We want to keep the stack pointing to the container
            // in the last key of the key path, since the last element
            // of the key path is a scalar, we clear the stack.
            stack_.clear();
        } else if (child.second.is_container()) {
            if ((i + 1) == limits_.max_container_depth) {
                break;
            }

            // Replace the stack top
            stack_.back() = detail::object_iterator::construct(
                child.second.ptr(), 0, limits_.max_container_size);

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
    if (current_.second.is_valid()) {
        for (const auto &p : path) { path_.emplace_back(p); }
    }
}

void kv_iterator::set_cursor_to_next_object()
{
    auto previous = current_;
    current_ = {};

    while (!stack_.empty() && current_.second.is_invalid()) {
        auto &it = stack_.back();

        if (!it.is_valid()) {
            // Pop can invalidate the parent references so after this point
            // they should not be used.
            stack_.pop_back();
            continue;
        }

        std::pair<std::string_view, object_view> child = *it;
        if (excluded_.contains(child.second.ptr())) {
            ++it;
            continue;
        }

        if (child.second.is_container()) {
            if (previous.second != child.second && !child.first.empty()) {
                current_ = {child.first, child.second};
                scalar_value_ = false;
                // Break to ensure the index isn't increased and this container
                // is fully iterated.
                break;
            }

            if (depth() < limits_.max_container_depth) {
                // Push can invalidate the current references to the parent
                // so we increment the index before a potential reallocation
                // and prevent any further use of the references.
                ++it;
                stack_.emplace_back(detail::object_iterator::construct(
                    child.second.ptr(), 0, limits_.max_container_size));
                continue;
            }
        } else if (child.second.is_scalar()) {
            if (previous.second != child.second) {
                current_ = {child.first, child.second};
                if (child.first.empty()) {
                    ++it;
                    scalar_value_ = true;
                } else {
                    scalar_value_ = false;
                }
                break;
            }

            if (!scalar_value_) {
                current_ = {child.first, child.second};
                scalar_value_ = true;
                break;
            }
        } else if (!child.first.empty()) {
            current_ = {child.first, child.second};
            scalar_value_ = false;
        }

        ++it;
    }
}
template class iterator_base<value_iterator>;
template class iterator_base<key_iterator>;
template class iterator_base<kv_iterator>;

} // namespace ddwaf
