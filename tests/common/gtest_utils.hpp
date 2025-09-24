// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <list>
#include <rapidjson/document.h>
#include <yaml-cpp/yaml.h>

#include "condition/base.hpp"
#include "condition/scalar_condition.hpp"
#include "ddwaf.h"

#include "common/base_utils.hpp"
#include "common/json_utils.hpp"
#include "common/yaml_utils.hpp"

#include "dynamic_string.hpp"

#define EXPECT_STR(a, b) EXPECT_EQ(std::string_view{a}, std::string_view{b})
#define EXPECT_STRV(a, b) EXPECT_STR(a, b)

namespace ddwaf::test {

struct event {
    struct match {
        struct argument {
            std::string name{"input"};
            dynamic_string value{};
            std::string address{};
            std::vector<std::string> path{};
        };
        std::string op{};
        std::string op_value{};
        dynamic_string highlight{};
        std::vector<argument> args;
    };

    std::string id;
    std::string name;
    std::string stack_id{};
    std::string block_id{};
    std::map<std::string, std::string> tags{{"type", ""}, {"category", ""}};
    std::vector<std::string> actions{};
    std::vector<match> matches;
};

using scalar_type = std::variant<bool, int64_t, uint64_t, double, std::string>;
using action_map = ::std::map<::std::string, ::std::map<::std::string, scalar_type>>;

bool operator==(const event::match::argument &lhs, const event::match::argument &rhs);
bool operator==(const event::match &lhs, const event::match &rhs);
bool operator==(const event &lhs, const event &rhs);

::std::ostream &operator<<(::std::ostream &os, const event &e);
::std::ostream &operator<<(::std::ostream &os, const event::match &m);

// Required by gtest to pretty print relevant types
void PrintTo(const ddwaf_object &actions, ::std::ostream *os);
void PrintTo(const std::list<ddwaf::test::event> &events, ::std::ostream *os);
void PrintTo(const std::list<ddwaf::test::event::match> &matches, ::std::ostream *os);

} // namespace ddwaf::test

::std::ostream &operator<<(::std::ostream &os, const ddwaf::test::action_map &actions);
void PrintTo(const ddwaf::test::action_map &actions, ::std::ostream *os);

namespace YAML {

template <> struct as_if<ddwaf::test::event::match, void> {
    explicit as_if(const Node &node_) : node(node_) {}
    ddwaf::test::event::match operator()() const;
    const Node &node;
};

template <> struct as_if<ddwaf::test::event, void> {
    explicit as_if(const Node &node_) : node(node_) {}
    ddwaf::test::event operator()() const;
    const Node &node;
};

template <> struct as_if<std::map<std::string, ddwaf::test::scalar_type>, void> {
    explicit as_if(const Node &node_) : node(node_) {}
    std::map<std::string, ddwaf::test::scalar_type> operator()() const;
    const Node &node;
};

template <> struct as_if<ddwaf::test::action_map, void> {
    explicit as_if(const Node &node_) : node(node_) {}
    ddwaf::test::action_map operator()() const;
    const Node &node;
};

} // namespace YAML

::testing::AssertionResult ValidateEventSchema(const std::string &result);
::testing::AssertionResult ValidateSchemaSchema(rapidjson::Document &doc);
::testing::AssertionResult ValidateDiagnosticsSchema(const ddwaf_object &diagnostics);
::testing::AssertionResult ValidateActionsSchema(const std::string &result);

class WafResultActionMatcher {
public:
    explicit WafResultActionMatcher(ddwaf::test::action_map &&v);
    bool MatchAndExplain(const ddwaf::test::action_map &, ::testing::MatchResultListener *) const;

    void DescribeTo(::std::ostream *os) const { *os << expected_; }
    void DescribeNegationTo(::std::ostream *os) const { *os << expected_; }

private:
    ddwaf::test::action_map expected_;
};

class WafResultDataMatcher {
public:
    explicit WafResultDataMatcher(std::vector<ddwaf::test::event> expected_events)
        : expected_events_(std::move(expected_events))
    {}

    bool MatchAndExplain(std::list<ddwaf::test::event>, ::testing::MatchResultListener *) const;

    void DescribeTo(::std::ostream *os) const
    {
        for (const auto &expected : expected_events_) { *os << expected; }
    }

    void DescribeNegationTo(::std::ostream *os) const
    {
        for (const auto &expected : expected_events_) { *os << expected; }
    }

protected:
    std::vector<ddwaf::test::event> expected_events_;
};

class MatchMatcher {
public:
    explicit MatchMatcher(std::vector<ddwaf::test::event::match> expected_matches)
        : expected_matches_(std::move(expected_matches))
    {}

    bool MatchAndExplain(
        std::list<ddwaf::test::event::match>, ::testing::MatchResultListener *) const;

    void DescribeTo(::std::ostream *os) const
    {
        for (const auto &expected : expected_matches_) { *os << expected; }
    }

    void DescribeNegationTo(::std::ostream *os) const
    {
        for (const auto &expected : expected_matches_) { *os << expected; }
    }

protected:
    std::vector<ddwaf::test::event::match> expected_matches_;
};

inline ::testing::PolymorphicMatcher<WafResultActionMatcher> WithActions(
    ddwaf::test::action_map &&values)
{
    return ::testing::MakePolymorphicMatcher(WafResultActionMatcher(std::move(values)));
}

inline ::testing::PolymorphicMatcher<WafResultDataMatcher> WithEvents(
    std::vector<ddwaf::test::event> &&expected)
{
    return ::testing::MakePolymorphicMatcher(WafResultDataMatcher(std::move(expected)));
}

inline ::testing::PolymorphicMatcher<MatchMatcher> WithMatches(
    std::vector<ddwaf::test::event::match> &&expected)
{
    return ::testing::MakePolymorphicMatcher(MatchMatcher(std::move(expected)));
}

std::list<ddwaf::test::event::match> from_matches(
    const std::vector<ddwaf::condition_match> &matches);

/*inline bool operator==(const ddwaf::test::scalar_type& left, const ddwaf::test::scalar_type&
 * right)*/
/*{*/
/*if (std::holds_alternative<std::string>(left)) {*/
/*return std::holds_alternative<std::string>(right) && std::get<std::string>(left) ==
 * std::get<std::string>(right);*/
/*}*/

/*if (std::holds_alternative<uint64_t>(left)) {*/
/*return std::holds_alternative<uint64_t>(right) && std::get<uint64_t>(left) ==
 * std::get<uint64_t>(right);*/
/*}*/

/*if (std::holds_alternative<int64_t>(left)) {*/
/*return std::holds_alternative<int64_t>(right) && std::get<int64_t>(left) ==
 * std::get<int64_t>(right);*/
/*}*/

/*if (std::holds_alternative<double>(left)) {*/
/*return std::holds_alternative<double>(right) && std::get<double>(left) ==
 * std::get<double>(right);*/
/*}*/

/*if (std::holds_alternative<bool>(left)) {*/
/*return std::holds_alternative<bool>(right) && std::get<bool>(left) == std::get<bool>(right);*/
/*}*/

/*return false;*/
/*}*/

/*template <typename T>*/
/*inline bool operator==(const ddwaf::test::scalar_type& left, const T& right)*/
/*{*/
/*return std::holds_alternative<T>(left) && std::get<T>(left) == right;*/
/*}*/

/*template <typename T>*/
/*inline bool operator==(const T& left, const ddwaf::test::scalar_type& right)*/
/*{*/
/*return std::holds_alternative<T>(right) && left == std::get<T>(right);*/
/*}*/

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define EXPECT_EVENTS(result, ...)                                                                 \
    {                                                                                              \
        const auto *object = ddwaf_object_find(&result, STRL("events"));                           \
        EXPECT_NE(object, nullptr);                                                                \
        auto data = ddwaf::test::object_to_json(*object);                                          \
        EXPECT_TRUE(ValidateEventSchema(data));                                                    \
        YAML::Node doc = YAML::Load(data.c_str());                                                 \
        auto events = doc.as<std::list<ddwaf::test::event>>();                                     \
        EXPECT_THAT(events, WithEvents({__VA_ARGS__}));                                            \
    }

#define EXPECT_MATCHES(matches, ...) EXPECT_THAT(from_matches(matches), WithMatches({__VA_ARGS__}));

#define EXPECT_SCHEMA_EQ(obtained, expected)                                                       \
    {                                                                                              \
        auto obtained_doc = test::object_to_rapidjson(obtained);                                   \
        EXPECT_TRUE(ValidateSchemaSchema(obtained_doc));                                           \
        rapidjson::Document expected_doc;                                                          \
        expected_doc.Parse(expected);                                                              \
        EXPECT_FALSE(expected_doc.HasParseError());                                                \
        EXPECT_TRUE(json_equals(obtained_doc, expected_doc)) << test::object_to_json(obtained);    \
    }

#define EXPECT_ACTIONS(result, ...)                                                                \
    {                                                                                              \
        const auto *object = ddwaf_object_find(&result, STRL("actions"));                          \
        EXPECT_NE(object, nullptr);                                                                \
        auto data = ddwaf::test::object_to_json(*object);                                          \
        EXPECT_TRUE(ValidateActionsSchema(data));                                                  \
        YAML::Node doc = YAML::Load(data.c_str());                                                 \
        auto obtained = doc.as<ddwaf::test::action_map>();                                         \
        EXPECT_THAT(obtained, WithActions(__VA_ARGS__));                                           \
    }

#define EXPECT_JSON(obtained, expected)                                                            \
    {                                                                                              \
        auto obtained_doc = test::object_to_rapidjson(obtained);                                   \
        rapidjson::Document expected_doc;                                                          \
        expected_doc.Parse(expected);                                                              \
        EXPECT_FALSE(expected_doc.HasParseError());                                                \
        EXPECT_TRUE(json_equals(obtained_doc, expected_doc)) << test::object_to_json(obtained);    \
    }

// NOLINTEND(cppcoreguidelines-macro-usage)
