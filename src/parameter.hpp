// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <exception.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ddwaf {

class parameter : public ddwaf_object {
public:
    typedef std::unordered_map<std::string_view, parameter> map;
    typedef std::vector<parameter> vector;
    typedef std::unordered_set<std::string_view> string_set;

    parameter() = default;
    parameter(const ddwaf_object &arg) { *((ddwaf_object *)this) = arg; }

    parameter(const parameter &) = default;
    parameter &operator=(const parameter &) = default;

    parameter(parameter &&) = delete;
    parameter operator=(parameter &&) = delete;

    void print();

    operator map();
    operator vector();
    operator string_set();
    operator std::string_view();
    operator std::string();
    operator uint64_t();
    operator bool();
    operator std::vector<std::string>();
    operator std::vector<std::string_view>();

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

} // namespace ddwaf
