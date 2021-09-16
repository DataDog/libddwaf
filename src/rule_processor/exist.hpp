// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef exist_hpp
#define exist_hpp

class Exist : public IPWRuleProcessor
{
    bool performMatch(const char*, size_t, MatchGatherer&) const override;

public:
    using IPWRuleProcessor::IPWRuleProcessor;

    bool buildProcessor(const rapidjson::Value&, bool) override;
    bool doesMatch(const ddwaf_object* pattern, MatchGatherer& gatherer) const override;
    bool doesMatchKey(const ddwaf_object* pattern, MatchGatherer& gatherer) const override;

    uint64_t expectedTypes() const override;

#ifdef TESTING
    FRIEND_TEST(TestRuleProcessor, TestExistCoverage);
#endif
};

#endif /* exist_hpp */
