// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include "rapidjson/prettywriter.h"
#include "rapidjson/schema.h"
#include "test.h"

using ddwaf_result_actions = ddwaf_result::_ddwaf_result_actions;

namespace ddwaf::test {
struct event {
    struct match {
        std::string op;
        std::string op_value;
        std::string address;
        std::vector<std::string> path;
        std::string value;
        std::string highlight;
    };

    std::string id;
    std::string name;
    std::string type;
    std::string category;
    std::vector<std::string> actions;
    std::vector<match> matches;
};

bool operator==(const event::match &lhs, const event::match &rhs);
bool operator==(const event &lhs, const event &rhs);

std::ostream &operator<<(std::ostream &os, const event &e);
} // namespace ddwaf::test

namespace YAML {

class parsing_error : public std::exception {
public:
    parsing_error(const std::string &what) : what_(what) {}
    const char *what() const noexcept { return what_.c_str(); }

protected:
    const std::string what_;
};

template <> struct as_if<ddwaf_object, void> {
    explicit as_if(const Node &node_);
    ddwaf_object operator()() const;
    const Node &node;
};

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

} // namespace YAML

class event_schema_validator {
public:
    event_schema_validator();
    std::optional<std::string> validate(const char *events);

protected:
    rapidjson::Document schema_doc_;
    std::unique_ptr<rapidjson::SchemaDocument> schema_;
    std::unique_ptr<rapidjson::SchemaValidator> validator_;
};

// Note that naming conventions (and Pascal case) are kept for functions and
// classes involved in anything GTest related.

::testing::AssertionResult ValidateSchema(const ddwaf_result &result);

// Required by gtest to pretty print relevant types
void PrintTo(const ddwaf_result_actions &actions, ::std::ostream *os);
void PrintTo(const ddwaf_result &result, ::std::ostream *os);

class WafResultActionMatcher {
public:
    WafResultActionMatcher(std::vector<std::string_view> &&values);
    bool MatchAndExplain(
        const ddwaf_result_actions &actions, ::testing::MatchResultListener *) const;

    void DescribeTo(::std::ostream *os) const { *os << expected_as_string_; }

    void DescribeNegationTo(::std::ostream *os) const { *os << expected_as_string_; }

private:
    std::string expected_as_string_;
    std::vector<std::string_view> expected_;
};

class WafResultDataMatcher {
public:
    WafResultDataMatcher(std::vector<ddwaf::test::event> expected_events)
        : expected_events_(std::move(expected_events))
    {}

    bool MatchAndExplain(const ddwaf_result &result, ::testing::MatchResultListener *) const;

    void DescribeTo(::std::ostream *os) const
    {
        for (auto expected : expected_events_) { *os << expected; }
    }

    void DescribeNegationTo(::std::ostream *os) const
    {
        for (auto expected : expected_events_) { *os << expected; }
    }

protected:
    std::vector<ddwaf::test::event> expected_events_;
};

inline ::testing::PolymorphicMatcher<WafResultActionMatcher> WithActions(
    std::vector<std::string_view> &&values)
{
    return ::testing::MakePolymorphicMatcher(WafResultActionMatcher(std::move(values)));
}

inline ::testing::PolymorphicMatcher<WafResultDataMatcher> WithEvents(
    std::vector<ddwaf::test::event> &&expected)
{
    return ::testing::MakePolymorphicMatcher(WafResultDataMatcher(std::move(expected)));
}

#define EXPECT_EVENTS(result, ...)                                                                 \
  EXPECT_TRUE(ValidateSchema(result));                                                             \
  EXPECT_THAT(result, WithEvents({__VA_ARGS__}));

ddwaf_object readFile(const char *filename);
ddwaf_object readRule(const char *rule);
