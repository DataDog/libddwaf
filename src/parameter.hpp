// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PARAMETER_H
#define PARAMETER_H

#include <ddwaf.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <exception.hpp>

namespace ddwaf
{

class parameter : public ddwaf_object
{
public:
    typedef std::unordered_map<std::string_view, parameter> map;
    typedef std::vector<parameter> vector;

    parameter() = default;
    parameter(const ddwaf_object& arg) { *((ddwaf_object*) this) = arg; }

    parameter(const parameter&) = default;
    parameter& operator=(const parameter&) = default;

    parameter(parameter&&) = delete;
    parameter operator=(parameter&&) = delete;

    void print();

    operator map();
    operator vector();
    operator std::string_view();
    operator std::string();

    ~parameter() = default;
};

template <typename T>
struct parameter_traits
{
    static const char* name() { return typeid(T).name(); }
};

template <>
struct parameter_traits<std::string>
{
    static const char* name() { return "std::string"; }
};

template <>
struct parameter_traits<std::string_view>
{
    static const char* name() { return "std::string_view"; }
};

template <>
struct parameter_traits<parameter::map>
{
    static const char* name() { return "parameter::map"; }
};

template <>
struct parameter_traits<parameter::vector>
{
    static const char* name() { return "parameter::vector"; }
};

template <typename T>
T at(parameter::map& map, const std::string& key)
{
    try
    {
        return map.at(key);
    }
    catch (const std::out_of_range& e)
    {
        throw missing_key(key);
    }
    catch (const bad_cast& e)
    {
        throw invalid_type(key, parameter_traits<T>::name());
    }
}

template <typename T>
T at(parameter::map& map, const std::string& key, const T& default_)
{
    auto it = map.find(key);
    return it == map.end() ? default_ : it->second;
}


}
#endif // PARAMETER_H
