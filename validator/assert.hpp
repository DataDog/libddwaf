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

#define expect(lhs, rhs) \
    try { \
        assert(lhs, rhs, __LINE__, __func__); \
    } catch (const assert_exception &e) { \
        throw; \
    } catch (const std::exception &e) { \
        throw assert_exception(e.what(), __LINE__, __func__); \
    }

class assert_exception : public std::exception
{
public:
    assert_exception(std::string_view what, int loc, std::string_view fn) {
        std::stringstream ss;
        ss << fn << "(" << loc << "): " << what;
        what_ = std::move(ss.str());
    }

    template <typename T>
    assert_exception(const T &lhs, const T &rhs, int loc, std::string_view fn) {
        std::stringstream ss;
        ss << fn << "(" << loc << "): " << lhs << " != " << rhs;
        what_ = std::move(ss.str());
    }
    const char* what() const noexcept override { return what_.c_str(); }

protected:
    std::string what_;
};


template<typename T>
inline void assert(const T &lhs, const T &rhs, int loc, std::string_view fn)
{
    if (lhs != rhs) { throw assert_exception(lhs, rhs, loc, fn); }
}

inline std::string to_string(bool val) { return val ? "true" : "false"; }

inline std::string to_string(DDWAF_RET_CODE val)
{
    switch(val) {
    case DDWAF_ERR_INTERNAL:
        return "internal error";
    case DDWAF_ERR_INVALID_OBJECT:
        return "invalid object";
    case DDWAF_ERR_INVALID_ARGUMENT:
        return "invalid argument";
    case DDWAF_GOOD:
        return "good";
    case DDWAF_MONITOR:
        return "monitor";
    case DDWAF_BLOCK:
        return "block";
    }
    return "unknown";
}

template<>
inline void assert(const bool &lhs, const bool &rhs, int loc, std::string_view fn)
{
    if (lhs != rhs) {
        throw assert_exception(to_string(lhs), to_string(rhs), loc, fn);
    }
}

template<>
inline void assert(const DDWAF_RET_CODE &lhs, const DDWAF_RET_CODE &rhs,
        int loc, std::string_view fn)
{
    if (lhs != rhs) {
        throw assert_exception(to_string(lhs), to_string(rhs), loc, fn);
    }
}

template<typename T>
inline void assert_yaml(const YAML::Node &lhs, const YAML::Node &rhs,
        int loc, std::string_view fn)
{
    auto lhs_value = lhs.as<T>();
    auto rhs_value = rhs.as<T>();

    if (lhs_value != rhs_value) {
        throw assert_exception(lhs, rhs, loc, fn);
    }
}

template<>
inline void assert<YAML::Node>(const YAML::Node &lhs, const YAML::Node &rhs,
        int loc, std::string_view fn)
{
    switch (lhs.Type()) {
    case YAML::NodeType::Sequence:
        assert_yaml<std::vector<std::string>>(lhs, rhs, loc, fn);
        break;
    case YAML::NodeType::Map:
        assert_yaml<std::map<std::string, std::string>>(lhs, rhs, loc, fn);
        break;
    case YAML::NodeType::Scalar:
    default:
        assert_yaml<std::string>(lhs, rhs, loc, fn);
        break;
    }
}
