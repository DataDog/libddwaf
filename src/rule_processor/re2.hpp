// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef re2_hpp
#define re2_hpp

#include <memory>
#include <re2/re2.h>

#include <utils.h>

class RE2Manager : public IPWRuleProcessor
{
public:
    using IPWRuleProcessor::IPWRuleProcessor;
    RE2Manager(const std::string& regex_str, bool caseSensitive);
    ~RE2Manager() = default;

    bool hasStringRepresentation() const override;
    const std::string getStringRepresentation() const override;
    const std::string& operatorName() const override { return name; }
#ifdef TESTING
    FRIEND_TEST(TestOptions, TestInit);
#endif
protected:
    bool performMatch(const char* str, size_t length, MatchGatherer& gatherer) const override;

protected:
    std::string name { "match_regex" };
    uint8_t groupsToCatch { 0 };
    std::unique_ptr<re2::RE2> regex { nullptr };
};

#endif /* re2_hpp */
