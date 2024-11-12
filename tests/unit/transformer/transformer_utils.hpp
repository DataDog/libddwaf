// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <gtest/gtest.h>

#include <array>
#include <string_view>
#include <transformer/common/cow_string.hpp>

// NOLINTBEGIN(hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)
//
// https://stackoverflow.com/questions/33484233/
template <std::size_t N, std::size_t... Is>
constexpr std::array<char, N - 1> literal_to_array(
    const char (&a)[N], std::index_sequence<Is...> /*unused*/)
{
    return {{a[Is]...}};
}

template <std::size_t N> constexpr std::array<char, N - 1> literal_to_array(const char (&a)[N])
{
    return literal_to_array(a, std::make_index_sequence<N - 1>());
}
// NOLINTEND(hicpp-avoid-c-arrays,modernize-avoid-c-arrays,cppcoreguidelines-avoid-c-arrays)

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define EXPECT_EVENTS(result, ...)                                                                 \
    {                                                                                              \
        auto data = ddwaf::test::object_to_json(result.events);                                    \
        EXPECT_TRUE(ValidateSchema(data));                                                         \
        YAML::Node doc = YAML::Load(data.c_str());                                                 \
        auto events = doc.as<std::list<ddwaf::test::event>>();                                     \
        EXPECT_ACTIONS(result, __VA_ARGS__)                                                        \
    }

#define EXPECT_TRANSFORM(name, source, expected)                                                   \
    {                                                                                              \
        {                                                                                          \
            cow_string str(std::string_view{source, sizeof(source) - 1});                          \
            EXPECT_TRUE(transformer::name::transform(str));                                        \
            EXPECT_STREQ(str.data(), expected);                                                    \
        }                                                                                          \
        if constexpr (sizeof(source) > 1) {                                                        \
            std::array<char, sizeof(source) - 1> copy{literal_to_array(source)};                   \
            cow_string str(std::string_view{copy.data(), copy.size()});                            \
            EXPECT_TRUE(transformer::name::transform(str)) << "Non nul-terminated string";         \
            EXPECT_STREQ(str.data(), expected) << "Non nul-terminated string";                     \
        }                                                                                          \
    }

#define EXPECT_NO_TRANSFORM(name, source)                                                          \
    {                                                                                              \
        {                                                                                          \
            cow_string str(std::string_view{source, sizeof(source) - 1});                          \
            EXPECT_FALSE(transformer::name::transform(str));                                       \
            EXPECT_FALSE(str.modified());                                                          \
        }                                                                                          \
        if constexpr (sizeof(source) > 1) {                                                        \
            std::array<char, sizeof(source) - 1> copy{literal_to_array(source)};                   \
            cow_string str(std::string_view{copy.data(), copy.size()});                            \
            EXPECT_FALSE(transformer::name::transform(str)) << "Non nul-terminated string";        \
            EXPECT_FALSE(str.modified());                                                          \
        }                                                                                          \
    }
// NOLINTEND(cppcoreguidelines-macro-usage)
