// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <stdexcept>
#include <iostream>
#include <sstream>
#include <string>
#include <string_view>

#include "utils.hpp"

#define expect_yaml(type, lhs, rhs, key) \
    assert_yaml<type>(lhs, rhs, key, __LINE__, __func__)

#define expect(lhs, rhs) \
    assert(lhs, rhs, __LINE__, __func__)

template <typename T>
class assert_exception : public std::exception
{
public:
    assert_exception(const T &lhs, const T &rhs, int loc, std::string_view fn) {
        std::stringstream ss;
        ss << fn << "(" << loc << "): " << lhs << " != " << rhs;
        what_ = std::move(ss.str());
    }
    const char* what() const noexcept { return what_.c_str(); }

protected:
    std::string what_;
};

template<typename T>
void assert(const T &lhs, const T &rhs, int loc, std::string_view fn) {
    if (lhs != rhs) { throw assert_exception(lhs, rhs, loc, fn); }
}

template <typename T>
void assert_yaml(const YAML::Node &lhs, const YAML::Node &rhs, 
    const std::string &key, int loc, std::string_view fn)
{
    auto lhs_val = lhs[key];
    auto rhs_val = rhs[key];
    auto lhs_str = lhs_val.as<T>();
    auto rhs_str = rhs_val.as<T>();

    if (lhs_str != rhs_str) {
        throw assert_exception(lhs_val, rhs_val, loc, fn);
    }
}


