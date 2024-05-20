// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <vector>

#include "ddwaf.h"
#include "iterator.hpp"
#include "object.hpp"

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
        object_view::iterator current;
        if (it.index() > 0) {
            current = it - 1;
        } else {
            current = it;
        }
        if (auto key = current.key(); key.is_string()) {
            keys.emplace_back(key.as_unchecked<std::string>());
        } else {
            // TODO intern these strings or use std::variant in the return
            keys.emplace_back(to_string<std::string>(current.index()));
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
    if (excluded_.contains(obj)) {
        return;
    }

    if (path.empty()) {
        if (obj.is_scalar()) {
            current_.second = obj;
            return;
        }

        // Uninitialised object...? We should throw an exception at some point
        if (!obj.is_container()) {
            return;
        }

        // Add container to stack and find next scalar
        if (limits_.max_container_depth > 0) {
            stack_.emplace_back(obj.begin(limits_.max_container_size));
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
    stack_.emplace_back(obj.begin(limits_.max_container_size));

    for (std::size_t i = 0; i < path.size(); i++) {
        const std::string_view key = path[i];
        auto &it = stack_.back();

        std::pair<object_view, object_view> child;
        for (; it.is_valid(); ++it) {
            auto [child_key, child_value] = *it;
            if (excluded_.contains(child_value)) {
                continue;
            }

            if (child_key.has_value() && child_key.as_unchecked<std::string_view>() == key) {
                child = {child_key, child_value};
                ++it;
                break;
            }
        }

        // If we find a scalar and it's the last element,
        // we found a valid element within the path.
        if (child.second.is_scalar() && (i + 1) == path.size()) {
            current_ = child;
            // We want to keep the stack pointing to the container
            // in the last key of the key path, since the last element
            // of the key path is a scalar, we clear the stack.
            stack_.clear();
        } else if (child.second.is_container()) {
            if ((i + 1) == limits_.max_container_depth) {
                break;
            }

            // Replace the stack top
            stack_.back() = child.second.begin(limits_.max_container_size);

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
    if (current_.second.is_valid()) {
        for (const auto &p : path) { path_.emplace_back(p); }
    }
}

void value_iterator::set_cursor_to_next_object()
{
    current_ = {};

    while (!stack_.empty() && current_.second.is_invalid()) {
        auto &it = stack_.back();
        if (!it.is_valid()) {
            // Pop can invalidate the iterator reference so after this point
            // it should not be used.
            stack_.pop_back();
        }

        auto [child_key, child_value] = *it;
        if (excluded_.contains(child_value)) {
            ++it;
            continue;
        }

        if (child_value.is_container()) {
            if (depth() < limits_.max_container_depth) {
                // Push can invalidate the current references to the parent
                // so we increment the index before a potential reallocation
                // and prevent any further use of the references.
                stack_.emplace_back(child_value.begin(limits_.max_container_size));
                ++it;
                continue;
            }
        } else if (child_value.is_scalar()) {
            current_ = {child_key, child_value};
        }

        ++it;
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
    if (excluded_.contains(obj)) {
        return;
    }

    if (!obj.is_container()) {
        return;
    }

    if (path.empty()) {
        // Add container to stack and find next scalar
        if (limits_.max_container_depth > 0) {
            stack_.emplace_back(obj.begin(limits_.max_container_size));
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
    stack_.emplace_back(obj.begin(limits_.max_container_size));

    for (std::size_t i = 0; i < path.size(); i++) {
        const std::string_view key = path[i];
        auto &it = stack_.back();

        std::pair<object_view, object_view> child;
        if (it.type() == object_type::map) {
            for (; it.is_valid(); ++it) {
                auto [child_key, child_value] = *it;
                if (child_key.is_invalid()) {
                    continue;
                }

                if (excluded_.contains(child_value)) {
                    continue;
                }

                if (child_key.as<std::string_view>() == key) {
                    child = {child_key, child_value};
                    break;
                }
            }
        }

        if (child.second.is_container()) {
            stack_.back() = child.second.begin(limits_.max_container_size);

            if ((i + 1) < path.size()) {
                continue;
            }

            set_cursor_to_next_object();
        }

        break;
    }

    // Once we reach this point, if current_ is valid, we found the key path
    if (current_.second.is_valid()) {
        for (const auto &p : path) { path_.emplace_back(p); }
    }
}

void key_iterator::set_cursor_to_next_object()
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

        auto [child_key, child_value] = *it;
        if (excluded_.contains(child_value)) {
            ++it;
            continue;
        }

        if (child_value.is_container()) {
            if (previous.second != child_value && child_key.is_valid()) {
                current_ = {child_key, child_value};
                // Break to ensure the index isn't increased and this container
                // is fully iterated.
                break;
            }

            if (depth() < limits_.max_container_depth) {
                // Push can invalidate the current references to the parent
                // so we increment the index before a potential reallocation
                // and prevent any further use of the references.
                ++it;
                stack_.emplace_back(child_value.begin(limits_.max_container_size));
                continue;
            }
        } else if (child_key.is_valid()) {
            current_ = {child_key, child_value};
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
    if (excluded_.contains(obj)) {
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
            stack_.emplace_back(obj.begin(limits_.max_container_size));
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
    stack_.emplace_back(obj.begin(limits_.max_container_size));

    for (std::size_t i = 0; i < path.size(); i++) {
        const std::string_view key = path[i];
        auto &it = stack_.back();

        std::pair<object_view, object_view> child;
        if (it.type() == object_type::map) {
            for (; it.is_valid(); ++it) {
                auto [child_key, child_value] = *it;

                if (child_key.is_invalid()) {
                    continue;
                }

                if (excluded_.contains(child_value)) {
                    continue;
                }

                if (child_key.as<std::string_view>() == key) {
                    child = {child_key, child_value};
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
            stack_.back() = child.second.begin(limits_.max_container_size);

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

        auto [child_key, child_value] = *it;
        if (excluded_.contains(child_value)) {
            ++it;
            continue;
        }

        if (child_value.is_container()) {
            if (previous.second != child_value && child_key.is_valid()) {
                current_ = {child_key, child_value};
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
                stack_.emplace_back(child_value.begin(limits_.max_container_size));
                continue;
            }
        } else if (child_value.is_scalar()) {
            if (previous.second != child_value) {
                current_ = {child_key, child_value};
                if (child_key.is_invalid()) {
                    ++it;
                    scalar_value_ = true;
                } else {
                    scalar_value_ = false;
                }
                break;
            }

            if (!scalar_value_) {
                current_ = {child_key, child_value};
                scalar_value_ = true;
                break;
            }
        } else if (child_key.is_valid()) {
            current_ = {child_key, child_value};
            scalar_value_ = false;
        }

        ++it;
    }
}
template class iterator_base<value_iterator>;
template class iterator_base<key_iterator>;
template class iterator_base<kv_iterator>;

} // namespace ddwaf
