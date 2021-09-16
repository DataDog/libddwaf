// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef ip_match_hpp
#define ip_match_hpp

#include <radixlib.h>

class IPMatch : public IPWRuleProcessor
{
    radix_tree_t* radixTree = nullptr;
    bool performMatch(const char* patternValue, size_t patternLength, MatchGatherer& gatherer) const override;

public:
    using IPWRuleProcessor::IPWRuleProcessor;
    ~IPMatch();
    bool buildProcessor(const rapidjson::Value& value, bool) override;
};

#endif /* ip_match_hpp */
