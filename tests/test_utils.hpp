// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#pragma once

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

std::ostream& operator<<(std::ostream& os, const event& e);
}

namespace YAML
{

class parsing_error : public std::exception
{
public:
    parsing_error(const std::string& what) : what_(what) {}
    const char* what() const noexcept { return what_.c_str(); }

protected:
    const std::string what_;
};

template <>
struct as_if<ddwaf_object, void>
{
    explicit as_if(const Node& node_);
    ddwaf_object operator()() const;
    const Node& node;
};

template <>
struct as_if<ddwaf::test::event::match, void>
{
    explicit as_if(const Node& node_): node(node_) {}
    ddwaf::test::event::match operator()() const;
    const Node& node;
};

template <>
struct as_if<ddwaf::test::event, void>
{
    explicit as_if(const Node& node_): node(node_) {}
    ddwaf::test::event operator()() const;
    const Node& node;
};

}

// Required by gtest to pretty print relevant types
void PrintTo(const ddwaf_result_actions &actions, ::std::ostream *os);
void PrintTo(const ddwaf_result &result, ::std::ostream *os);

class WafResultActionMatcher {
public:
    WafResultActionMatcher(std::vector<std::string_view> &&values);
    bool MatchAndExplain(const ddwaf_result_actions &actions,
      ::testing::MatchResultListener*) const;

    void DescribeTo(::std::ostream* os) const {
        *os << expected_as_string_;
    }

    void DescribeNegationTo(::std::ostream* os) const {
        *os << expected_as_string_;
    }

private:
    std::string expected_as_string_;
    std::vector<std::string_view> expected_;
};

class WafResultDataMatcher {
public:
    WafResultDataMatcher(ddwaf::test::event expected):
        expected_(std::move(expected)) {}

    bool MatchAndExplain(const ddwaf_result &result,
      ::testing::MatchResultListener*) const;

    void DescribeTo(::std::ostream* os) const {
        *os << expected_;
    }

    void DescribeNegationTo(::std::ostream* os) const {
        *os << expected_;
    }

protected:
    ddwaf::test::event expected_;
};


inline ::testing::PolymorphicMatcher<WafResultActionMatcher> WithActions(
  std::vector<std::string_view> &&values) {
    return ::testing::MakePolymorphicMatcher(
        WafResultActionMatcher(std::move(values)));
}

inline ::testing::PolymorphicMatcher<WafResultDataMatcher> WithEvent(
    ddwaf::test::event &&expected) {
    return ::testing::MakePolymorphicMatcher(
        WafResultDataMatcher(std::move(expected)));
}

ddwaf_object readFile(const char* filename);
ddwaf_object readRule(const char* rule);
