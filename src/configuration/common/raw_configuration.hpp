// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "configuration/common/parser_exception.hpp"
#include "object.hpp"
#include "semver.hpp"

namespace ddwaf {

class raw_configuration {
public:
    using map = std::unordered_map<std::string_view, raw_configuration>;
    using vector = std::vector<raw_configuration>;
    using string_set = std::unordered_set<std::string_view>;

    raw_configuration() = default;
    ~raw_configuration() = default;
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    raw_configuration(object_view view) : view_(view) {}
    // NOLINTNEXTLINE(google-explicit-constructor,hicpp-explicit-conversions)
    raw_configuration(const ddwaf_object &obj) : view_(&obj) {}
    raw_configuration(const raw_configuration &) = default;
    raw_configuration &operator=(const raw_configuration &) = default;

    raw_configuration(raw_configuration &&other) noexcept = delete;
    raw_configuration &operator=(raw_configuration &&other) noexcept = delete;

    explicit operator map() const;
    explicit operator vector() const;
    explicit operator string_set() const;
    explicit operator std::string_view() const;
    explicit operator std::string() const;
    explicit operator uint64_t() const;
    explicit operator int64_t() const;
    explicit operator double() const;
    explicit operator bool() const;
    explicit operator std::vector<std::string>() const;
    explicit operator std::vector<std::string_view>() const;
    explicit operator std::unordered_map<std::string, std::string>() const;
    explicit operator semantic_version() const;

    const object_view *operator->() const { return &view_; }

protected:
    object_view view_;
};

template <typename T> struct raw_configuration_traits {
    static const char *name() { return typeid(T).name(); }
};

template <> struct raw_configuration_traits<std::string> {
    static const char *name() { return "std::string"; }
};

template <> struct raw_configuration_traits<std::string_view> {
    static const char *name() { return "std::string_view"; }
};

template <> struct raw_configuration_traits<raw_configuration::map> {
    static const char *name() { return "parameter::map"; }
};

template <> struct raw_configuration_traits<raw_configuration::vector> {
    static const char *name() { return "parameter::vector"; }
};

template <> struct raw_configuration_traits<raw_configuration::string_set> {
    static const char *name() { return "parameter::string_set"; }
};

template <> struct raw_configuration_traits<std::vector<std::string>> {
    static const char *name() { return "std::vector<std::string>"; }
};

template <> struct raw_configuration_traits<std::vector<std::string_view>> {
    static const char *name() { return "std::vector<std::string_view>"; }
};

template <> struct raw_configuration_traits<std::unordered_map<std::string, std::string>> {
    static const char *name() { return "std::unordered_map<std::string, std::string>"; }
};

template <> struct raw_configuration_traits<semantic_version> {
    static const char *name() { return "semantic_version"; }
};

} // namespace ddwaf
