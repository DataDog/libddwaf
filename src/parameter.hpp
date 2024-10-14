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

#include "ddwaf.h"
#include "exception.hpp"
#include "semver.hpp"

namespace ddwaf {

class parameter : public ddwaf_object {
public:
    using map = std::unordered_map<std::string_view, parameter>;
    using vector = std::vector<parameter>;
    using string_set = std::unordered_set<std::string_view>;

    parameter() = default;
    // NOLINTNEXTLINE(google-explicit-constructor)
    parameter(const ddwaf_object &arg) : _ddwaf_object() { *((ddwaf_object *)this) = arg; }

    parameter(const parameter &) = default;
    parameter &operator=(const parameter &) = default;

    parameter(parameter &&) = delete;
    parameter operator=(parameter &&) = delete;

    void print();

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

    ~parameter() = default;
};

template <typename T> struct parameter_traits {
    static const char *name() { return typeid(T).name(); }
};

template <> struct parameter_traits<std::string> {
    static const char *name() { return "std::string"; }
};

template <> struct parameter_traits<std::string_view> {
    static const char *name() { return "std::string_view"; }
};

template <> struct parameter_traits<parameter::map> {
    static const char *name() { return "parameter::map"; }
};

template <> struct parameter_traits<parameter::vector> {
    static const char *name() { return "parameter::vector"; }
};

template <> struct parameter_traits<parameter::string_set> {
    static const char *name() { return "parameter::string_set"; }
};

template <> struct parameter_traits<std::vector<std::string>> {
    static const char *name() { return "std::vector<std::string>"; }
};

template <> struct parameter_traits<std::vector<std::string_view>> {
    static const char *name() { return "std::vector<std::string_view>"; }
};

template <> struct parameter_traits<std::unordered_map<std::string, std::string>> {
    static const char *name() { return "std::unordered_map<std::string, std::string>"; }
};

template <> struct parameter_traits<semantic_version> {
    static const char *name() { return "semantic_version"; }
};

} // namespace ddwaf
