// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <re2/re2.h>

#include <utils.h>

class RE2Manager : public IPWRuleProcessor
{
public:
    RE2Manager(const std::string& regex_str, std::size_t minLength, bool caseSensitive);
    ~RE2Manager() = default;

    bool hasStringRepresentation() const override;
    const std::string getStringRepresentation() const override;
    std::string_view operatorName() const override { return name; }
#ifdef TESTING
    FRIEND_TEST(TestOptions, TestInit);
#endif
protected:
    bool performMatch(const char* str, size_t length, MatchGatherer& gatherer) const override;

protected:
    static constexpr std::string_view name { "match_regex" };
    uint8_t groupsToCatch { 0 };
    std::unique_ptr<re2::RE2> regex { nullptr };
    std::size_t min_length;
};
