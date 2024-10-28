// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2024 Datadog, Inc.

#pragma once

#include "utils.hpp"

#include <string>
#include <type_traits>
#include <unordered_map>

namespace ddwaf {

using target_index = std::size_t;

inline target_index get_target_index(std::string_view address)
{
    return std::hash<std::string_view>{}(address);
}

struct target_address {
    explicit target_address(std::string name_)
        : name(std::move(name_)), index(get_target_index(name))
    {}

    auto operator<=>(const target_address &o) const { return name <=> o.name; }
    bool operator==(const target_address &o) const { return index == o.index && name == o.name; }

    std::string name;
    target_index index;
};

struct target_address_view {
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    target_address_view(const target_address &address) : name(address.name), index(address.index) {}

    auto operator<=>(const target_address_view &o) const { return name <=> o.name; }
    auto operator<=>(const target_address &o) const { return name <=> o.name; }

    template <typename T>
    bool operator==(const T &o) const
        requires std::is_same_v<target_address, T> || std::is_same_v<target_address_view, T>
    {
        return index == o.index && name == o.name;
    }

    std::string_view name;
    target_index index;
};

} // namespace ddwaf

namespace std {
template <> struct hash<ddwaf::target_address> {
    size_t operator()(const ddwaf::target_address &addr) const { return addr.index; }
};

template <> struct hash<ddwaf::target_address_view> {
    size_t operator()(const ddwaf::target_address_view &addr) const { return addr.index; }
};
} // namespace std
