// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "object.hpp"
#include "object_type.hpp"

namespace ddwaf {

template <typename T>
iterator_base<T>::iterator_base(const object_set_ref &exclude) : excluded_(exclude)
{
    stack_.reserve(initial_stack_size);
}

template <typename T> bool iterator_base<T>::operator++()
{
    if (current_.second.has_value()) {
        T &derived = static_cast<T &>(*this);
        derived.set_cursor_to_next_object();
    }
    return current_.second.has_value();
}

template <typename T>
std::vector<std::variant<std::string_view, int64_t>> iterator_base<T>::get_current_path() const
{
    if (!current_.second.has_value()) {
        return {};
    }

    std::vector<std::variant<std::string_view, int64_t>> keys;
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
        auto [key, child] = parent.at(parent_index - 1);
        if (parent.type() == object_type::map) {
            keys.emplace_back(key.template as<std::string_view>());
        } else {
            keys.emplace_back(static_cast<int64_t>(parent_index - 1));
        }
        parent = stack_[i].first;
        parent_index = stack_[i].second;
    }

    if (parent.type() == object_type::map) {
        keys.emplace_back(current_.first.as<std::string_view>());
    } else {
        keys.emplace_back(static_cast<int64_t>(parent_index - 1));
    }

    return keys;
}

value_iterator::value_iterator(object_view obj,
    std::span<const std::variant<std::string, int64_t>> path, const object_set_ref &exclude)
    : iterator_base(exclude)
{
    initialise_cursor(obj, path);
}

void value_iterator::initialise_cursor(
    object_view obj, std::span<const std::variant<std::string, int64_t>> path)
{
    if (excluded_.contains(obj.ptr())) {
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
        stack_.emplace_back(obj, 0);
        set_cursor_to_next_object();
    } else {
        initialise_cursor_with_path(obj, path);
    }
}

void value_iterator::initialise_cursor_with_path(
    object_view obj, std::span<const std::variant<std::string, int64_t>> path)
{
    // An object with a path should always start with a container
    if (!obj.is_container()) {
        return;
    }

    // Add container to stack and find next scalar within the given path
    stack_.emplace_back(obj, 0);

    for (std::size_t i = 0; i < path.size(); i++) {
        const auto &key = path[i];
        auto &[parent, index] = stack_.back();

        std::pair<object_view, object_view> child;
        if (parent.is_map() && std::holds_alternative<std::string>(key)) {
            const auto &expected_key = std::get<std::string>(key);
            for (std::size_t j = 0; j < parent.size(); j++) {
                auto possible_child = parent.at(j);
                if (!possible_child.first.has_value()) {
                    continue;
                }

                if (excluded_.contains(possible_child.second)) {
                    continue;
                }

                if (possible_child.first == expected_key) {
                    child = possible_child;
                    index = j + 1;
                    break;
                }
            }
        } else if (parent.is_array() && std::holds_alternative<int64_t>(key)) {
            const auto expected_index = std::get<int64_t>(key);
            if (expected_index >= 0 && parent.size<int64_t>() > expected_index) {
                child = parent.at(expected_index);
                index = expected_index;
            } else if (expected_index < 0 && (parent.size<int64_t>() + expected_index) >= 0) {
                index = parent.size<int64_t>() + expected_index;
                child = parent.at(index);
            }
        }

        if (!child.second.has_value()) {
            return;
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
            // Replace the stack top
            stack_.back() = {child.second, 0};

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
    if (current_.second.has_value()) {
        for (const auto &p : path) {
            if (std::holds_alternative<std::string>(p)) {
                path_.emplace_back(std::get<std::string>(p));
            } else {
                path_.emplace_back(std::get<int64_t>(p));
            }
        }
    }
}

void value_iterator::set_cursor_to_next_object()
{
    current_ = {};

    while (!stack_.empty() && !current_.second.has_value()) {
        auto &[parent, index] = stack_.back();
        if (index >= parent.size()) {
            // Pop can invalidate the parent references so after this point
            // they should not be used.
            stack_.pop_back();
            continue;
        }

        auto child = parent.at_value(index);
        if (excluded_.contains(child)) {
            ++index;
            continue;
        }

        if (child.is_container()) {
            ++index;
            // Push can invalidate the current references to the parent
            // so we increment the index before a potential reallocation
            // and prevent any further use of the references.
            stack_.emplace_back(child, 0);
            continue;
        }

        if (child.is_scalar()) {
            current_.first = parent.at_key(index);
            current_.second = child;
        }

        ++index;
    }
}

key_iterator::key_iterator(object_view obj,
    std::span<const std::variant<std::string, int64_t>> path, const object_set_ref &exclude)
    : iterator_base(exclude)
{
    initialise_cursor(obj, path);
}

void key_iterator::initialise_cursor(
    object_view obj, std::span<const std::variant<std::string, int64_t>> path)
{
    if (excluded_.contains(obj.ptr())) {
        return;
    }

    if (!obj.is_container()) {
        return;
    }

    if (path.empty()) {
        // Add container to stack and find next scalar
        stack_.emplace_back(obj, 0);
        set_cursor_to_next_object();
    } else {
        initialise_cursor_with_path(obj, path);
    }
}

void key_iterator::initialise_cursor_with_path(
    object_view obj, std::span<const std::variant<std::string, int64_t>> path)
{
    // Add container to stack and find next scalar within the given path
    stack_.emplace_back(obj, 0);

    for (std::size_t i = 0; i < path.size(); i++) {
        const auto &key = path[i];
        auto &[parent, index] = stack_.back();

        std::pair<object_view, object_view> child;
        if (parent.is_map() && std::holds_alternative<std::string>(key)) {
            const auto &expected_key = std::get<std::string>(key);
            for (std::size_t j = 0; j < parent.size(); j++) {
                auto possible_child = parent.at(j);
                ;
                if (!possible_child.first.has_value()) {
                    continue;
                }

                if (excluded_.contains(possible_child.second)) {
                    continue;
                }

                if (possible_child.first == expected_key) {
                    child = possible_child;
                    break;
                }
            }
        } else if (parent.is_array() && std::holds_alternative<int64_t>(key)) {
            const auto expected_index = std::get<int64_t>(key);
            if (expected_index >= 0 && parent.size<int64_t>() > expected_index) {
                child = parent.at(expected_index);
            } else if (expected_index < 0 && (parent.size<int64_t>() + expected_index) >= 0) {
                child = parent.at(parent.size<int64_t>() + expected_index);
            }
        }

        if (!child.second.has_value()) {
            return;
        }

        if (child.second.is_container()) {
            stack_.back() = {child.second, 0};

            if ((i + 1) < path.size()) {
                continue;
            }

            set_cursor_to_next_object();
        }

        break;
    }

    // Once we reach this point, if current_ is valid, we found the key path
    if (current_.second.has_value()) {
        for (const auto &p : path) {
            if (std::holds_alternative<std::string>(p)) {
                path_.emplace_back(std::get<std::string>(p));
            } else {
                path_.emplace_back(std::get<int64_t>(p));
            }
        }
    }
}

void key_iterator::set_cursor_to_next_object()
{
    auto previous = current_;
    current_ = {};

    while (!stack_.empty() && !current_.second.has_value()) {
        auto &[parent, index] = stack_.back();

        if (index >= parent.size()) {
            // Pop can invalidate the parent references so after this point
            // they should not be used.
            stack_.pop_back();
            continue;
        }

        auto child = parent.at(index);
        if (excluded_.contains(child.second.ptr())) {
            ++index;
            continue;
        }

        if (child.second.is_container()) {
            if (previous.second != child.second && child.first.has_value()) {
                current_ = child;
                // Break to ensure the index isn't increased and this container
                // is fully iterated.
                break;
            }

            // Push can invalidate the current references to the parent
            // so we increment the index before a potential reallocation
            // and prevent any further use of the references.
            ++index;
            stack_.emplace_back(child.second, 0);
            continue;
        }

        if (child.first.has_value()) {
            current_ = child;
        }

        ++index;
    }
}

kv_iterator::kv_iterator(object_view obj, std::span<const std::variant<std::string, int64_t>> path,
    const object_set_ref &exclude)
    : iterator_base(exclude)
{
    initialise_cursor(obj, path);
}

void kv_iterator::initialise_cursor(
    object_view obj, std::span<const std::variant<std::string, int64_t>> path)
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
        stack_.emplace_back(obj, 0);
        set_cursor_to_next_object();
    } else {
        initialise_cursor_with_path(obj, path);
    }
}

void kv_iterator::initialise_cursor_with_path(
    object_view obj, std::span<const std::variant<std::string, int64_t>> path)
{
    // Add container to stack and find next scalar within the given path
    stack_.emplace_back(obj, 0);

    for (std::size_t i = 0; i < path.size(); i++) {
        const auto &key = path[i];
        auto &[parent, index] = stack_.back();

        std::pair<object_view, object_view> child;
        if (parent.is_map() && std::holds_alternative<std::string>(key)) {
            const auto &expected_key = std::get<std::string>(key);
            for (std::size_t j = 0; j < parent.size(); j++) {
                auto possible_child = parent.at(j);
                if (!possible_child.first.has_value()) {
                    continue;
                }

                if (excluded_.contains(possible_child.second)) {
                    continue;
                }

                if (possible_child.first == expected_key) {
                    child = possible_child;
                    break;
                }
            }
        } else if (parent.is_array() && std::holds_alternative<int64_t>(key)) {
            const auto expected_index = std::get<int64_t>(key);
            if (expected_index >= 0 && parent.size<int64_t>() > expected_index) {
                child = parent.at(expected_index);
            } else if (expected_index < 0 && (parent.size<int64_t>() + expected_index) >= 0) {
                child = parent.at(parent.size<int64_t>() + expected_index);
            }
        }

        if (!child.second.has_value()) {
            return;
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
            // Replace the stack top
            stack_.back() = {child.second, 0};

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
    if (current_.second.has_value()) {
        for (const auto &p : path) {
            if (std::holds_alternative<std::string>(p)) {
                path_.emplace_back(std::get<std::string>(p));
            } else {
                path_.emplace_back(std::get<int64_t>(p));
            }
        }
    }
}

void kv_iterator::set_cursor_to_next_object()
{
    auto previous = current_;
    current_ = {};

    while (!stack_.empty() && !current_.second.has_value()) {
        auto &[parent, index] = stack_.back();

        if (index >= parent.size()) {
            // Pop can invalidate the parent references so after this point
            // they should not be used.
            stack_.pop_back();
            continue;
        }

        auto child = parent.at(index);
        if (excluded_.contains(child.second.ptr())) {
            ++index;
            continue;
        }

        if (child.second.is_container()) {
            if (previous.second != child.second && child.first.has_value()) {
                current_ = child;
                scalar_value_ = false;
                // Break to ensure the index isn't increased and this container
                // is fully iterated.
                break;
            }

            // Push can invalidate the current references to the parent
            // so we increment the index before a potential reallocation
            // and prevent any further use of the references.
            ++index;
            stack_.emplace_back(child.second, 0);
            continue;
        }

        if (child.second.is_scalar()) {
            if (previous.second != child.second) {
                current_ = child;
                if (!child.first.has_value()) {
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
        } else if (child.first.has_value()) {
            current_ = child;
            scalar_value_ = false;
        }

        ++index;
    }
}
template class iterator_base<value_iterator>;
template class iterator_base<key_iterator>;
template class iterator_base<kv_iterator>;

} // namespace ddwaf
