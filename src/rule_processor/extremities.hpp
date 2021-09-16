// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef extremities_h
#define extremities_h

class ExtremitiesMatch : public IPWRuleProcessor
{
protected:
    std::string value;

    virtual bool matchString(const char* pattern, size_t length) const = 0;

    bool performMatch(const char* pattern, size_t length, MatchGatherer& gatherer) const override;

public:
    using IPWRuleProcessor::IPWRuleProcessor;
    bool buildProcessor(const rapidjson::Value&, bool) override;
    bool hasStringRepresentation() const override;
    const std::string getStringRepresentation() const override;
};

class BeginsWith : public ExtremitiesMatch
{
    using ExtremitiesMatch::ExtremitiesMatch;
    bool matchString(const char* pattern, size_t patternLength) const override;
};

class Contains : public ExtremitiesMatch
{
    using ExtremitiesMatch::ExtremitiesMatch;
    bool matchString(const char* pattern, size_t patternLength) const override;
};

class EndsWith : public ExtremitiesMatch
{
    using ExtremitiesMatch::ExtremitiesMatch;
    bool matchString(const char* pattern, size_t patternLength) const override;
};

#endif /* extremities_h */
