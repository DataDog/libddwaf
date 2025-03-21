// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include "object.hpp"
#include "ddwaf.h"
#include "object_type.hpp"

#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <new>
#include <string_view>
#include <utility>

namespace ddwaf {

namespace detail {

using object = ddwaf_object;

char *copy_string(const char *str, std::size_t len)
{
    // TODO new char[len];
    if (len == SIZE_MAX) {
        throw std::bad_alloc();
    }

    // NOLINTNEXTLINE(hicpp-no-malloc)
    char *copy = static_cast<char *>(malloc(len + 1));
    if (copy == nullptr) [[unlikely]] {
        throw std::bad_alloc();
    }

    memcpy(copy, str, len);
    copy[len] = '\0';

    return copy;
}

void realloc_array(object &obj)
{
    static constexpr std::size_t array_increment = 8;

    const auto size = static_cast<std::size_t>(obj.nbEntries) + array_increment;
    if (size > SIZE_MAX / sizeof(object)) [[unlikely]] {
        throw std::bad_alloc();
    }

    auto *new_array = static_cast<object *>(
        // NOLINTNEXTLINE(hicpp-no-malloc)
        realloc(static_cast<void *>(obj.array), size * sizeof(object)));
    if (new_array == nullptr) [[unlikely]] {
        throw std::bad_alloc();
    }

    obj.array = new_array;
}

void alloc_array(object &obj)
{
    static constexpr std::size_t array_start_size = 8;
    // NOLINTNEXTLINE(hicpp-no-malloc)
    obj.array = static_cast<object *>(malloc(array_start_size * sizeof(object)));
    if (obj.array == nullptr) [[unlikely]] {
        throw std::bad_alloc();
    }
}

} // namespace detail

template <typename Derived> [[nodiscard]] owned_object readable_object<Derived>::clone() const
{
    auto clone_helper = [](object_view source) -> owned_object {
        switch (source.type()) {
        case object_type::boolean:
            return owned_object::make_boolean(source.as<bool>());
        case object_type::string:
            return owned_object::make_string(source.as<std::string_view>());
        case object_type::int64:
            return owned_object::make_signed(source.as<int64_t>());
        case object_type::uint64:
            return owned_object::make_unsigned(source.as<uint64_t>());
        case object_type::float64:
            return owned_object::make_float(source.as<double>());
        case object_type::null:
            return owned_object::make_null();
        case object_type::map:
            return owned_object::make_map();
        case object_type::array:
            return owned_object::make_array();
        case object_type::invalid:
            break;
        }
        return {};
    };

    std::deque<std::pair<object_view, borrowed_object>> queue;

    object_view input = static_cast<const Derived *>(this)->ref();
    auto copy = clone_helper(input);
    if (copy.is_container()) {
        queue.emplace_front(input, copy);
    }

    while (!queue.empty()) {
        auto &[source, destination] = queue.front();
        for (uint64_t i = 0; i < source.size(); ++i) {
            const auto &[key, value] = source.at(i);
            if (source.type() == object_type::map) {
                destination.emplace(key.as<std::string_view>(), clone_helper(value));
            } else if (source.type() == object_type::array) {
                destination.emplace_back(clone_helper(value));
            }
        }

        for (uint64_t i = 0; i < source.size(); ++i) {
            auto child = source.at_value(i);
            if (child.is_container()) {
                queue.emplace_back(child, destination.at(i));
            }
        }

        queue.pop_front();
    }

    return copy;
}

template <typename Derived>
[[nodiscard]] borrowed_object writable_object<Derived>::at(std::size_t idx)
{
    auto &container = static_cast<const Derived *>(this)->ref();

    assert((static_cast<object_type>(container.type) & container_object_type) != 0);
    assert(idx < static_cast<std::size_t>(container.nbEntries));

    return borrowed_object{&container.array[idx]};
}

template <typename Derived>
// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
borrowed_object writable_object<Derived>::emplace_back(owned_object &&value)
{
    auto &container = static_cast<Derived *>(this)->ref();

    assert(static_cast<object_type>(container.type) == object_type::array);

    // We preallocate 8 entries
    if (container.nbEntries == 0) {
        [[unlikely]] detail::alloc_array(container);
    }
    // If we're exceeding our preallocation, add 8 more
    else if ((container.nbEntries & 0x7) == 0) {
        detail::realloc_array(container);
    }

    auto *slot = &container.array[container.nbEntries++];
    memcpy(slot, value.ptr(), sizeof(detail::object));

    // The object has to be explicitly moved, otherwise the contents will be freed
    // on return, causing the inserted object to be invalid
    value.move();

    return borrowed_object{slot};
}

template <typename Derived>
// NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
borrowed_object writable_object<Derived>::emplace(std::string_view key, owned_object &&value)
{
    auto &container = static_cast<Derived *>(this)->ref();
    assert(static_cast<object_type>(container.type) == object_type::map);

    // We preallocate 8 entries
    if (container.nbEntries == 0) {
        [[unlikely]] detail::alloc_array(container);
    }
    // If we're exceeding our preallocation, add 8 more
    else if ((container.nbEntries & 0x7) == 0) {
        detail::realloc_array(container);
    }

    auto *value_ptr = value.ptr();
    value_ptr->parameterName = detail::copy_string(key.data(), key.size());
    value_ptr->parameterNameLength = key.size();

    auto *slot = &container.array[container.nbEntries++];
    memcpy(slot, value.ptr(), sizeof(detail::object));

    // The object has to be explicitly moved, otherwise the contents will be freed
    // on return, causing the inserted object to be invalid
    value.move();

    return borrowed_object{slot};
}

template class readable_object<owned_object>;
template class readable_object<borrowed_object>;
template class readable_object<object_view>;

template class writable_object<owned_object>;
template class writable_object<borrowed_object>;

} // namespace ddwaf
