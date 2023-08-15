// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

#include <map>
#include <utility>
#include <vector>

#include <rapidjson/prettywriter.h>
#include <rapidjson/schema.h>

#include <yaml-cpp/yaml.h>

#include "context_allocator.hpp"
#include "ddwaf.h"
#include "event.hpp"
#include "test.hpp"

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
    std::map<std::string, std::string> tags{{"type", ""}, {"category", ""}};
    std::vector<std::string> actions;
    std::vector<match> matches;
};

bool operator==(const event::match &lhs, const event::match &rhs);
bool operator==(const event &lhs, const event &rhs);

std::ostream &operator<<(std::ostream &os, const event &e);
std::ostream &operator<<(std::ostream &os, const event::match &m);

std::string object_to_json(const ddwaf_object &obj);
rapidjson::Document object_to_rapidjson(const ddwaf_object &obj);

} // namespace ddwaf::test

namespace YAML {

class parsing_error : public std::exception {
public:
    explicit parsing_error(std::string what) : what_(std::move(what)) {}
    [[nodiscard]] const char *what() const noexcept override { return what_.c_str(); }

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

class schema_validator {
public:
    explicit schema_validator(const std::string &path);
    std::optional<std::string> validate(const char *events);
    std::optional<std::string> validate(rapidjson::Document &doc);

protected:
    rapidjson::Document schema_doc_;
    std::unique_ptr<rapidjson::SchemaDocument> schema_;
    std::unique_ptr<rapidjson::SchemaValidator> validator_;
};

// Note that naming conventions (and Pascal case) are kept for functions and
// classes involved in anything GTest related.

::testing::AssertionResult ValidateSchema(const std::string &result);
::testing::AssertionResult ValidateSchemaSchema(rapidjson::Document &doc);

// Required by gtest to pretty print relevant types
void PrintTo(const ddwaf_object &actions, ::std::ostream *os);
void PrintTo(const std::list<ddwaf::test::event> &events, ::std::ostream *os);
void PrintTo(const std::list<ddwaf::test::event::match> &matches, ::std::ostream *os);

class WafResultActionMatcher {
public:
    explicit WafResultActionMatcher(std::vector<std::string_view> &&values);
    bool MatchAndExplain(const ddwaf_object &actions, ::testing::MatchResultListener *) const;

    void DescribeTo(::std::ostream *os) const { *os << expected_as_string_; }

    void DescribeNegationTo(::std::ostream *os) const { *os << expected_as_string_; }

private:
    std::string expected_as_string_{};
    std::vector<std::string_view> expected_;
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
    std::vector<std::string_view> &&values)
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
    const ddwaf::memory::vector<ddwaf::event::match> &matches);

// NOLINTBEGIN(cppcoreguidelines-macro-usage)
#define EXPECT_EVENTS(result, ...)                                                                 \
  {                                                                                                \
    auto data = ddwaf::test::object_to_json(result.events);                                        \
    EXPECT_TRUE(ValidateSchema(data));                                                             \
    YAML::Node doc = YAML::Load(data.c_str());                                                     \
    auto events = doc.as<std::list<ddwaf::test::event>>();                                         \
    EXPECT_THAT(events, WithEvents({__VA_ARGS__}));                                                \
  }

#define EXPECT_MATCHES(matches, ...) EXPECT_THAT(from_matches(matches), WithMatches({__VA_ARGS__}));
// NOLINTEND(cppcoreguidelines-macro-usage)

ddwaf_object read_file(std::string_view filename, std::string_view base = "./");

inline ddwaf_object yaml_to_object(const std::string &yaml)
{
    return YAML::Load(yaml).as<ddwaf_object>();
}

ddwaf_object json_to_object(const std::string &json);
