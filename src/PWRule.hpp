// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#ifndef PWRule_hpp
#define PWRule_hpp

#include <memory>
#include <string>
#include <vector>

struct PWRule;

#include <Clock.hpp>
#include <IPWRuleProcessor.h>
#include <PWManifest.h>
#include <PWRet.hpp>
#include <PWRetriever.hpp>
#include <PWTransformer.h>

// Expect `1 << (MAX_MATCH_COUNT - 1)` to fit in 16 bits

enum PWRULE_MATCH_STATUS
{
    MISSING_ARG,
    TIMEOUT,
    MATCHED,
    NO_MATCH
};

struct PWRule
{
    bool initialized;

    struct
    {
        uint64_t minLength         = 0;
        bool keepRunningOnMatch    = false;
        bool matchInterTransformer = false;
    } options;

    std::vector<PWManifest::ARG_ID> targets;
    std::vector<PW_TRANSFORM_ID> transformation;
    std::unique_ptr<IPWRuleProcessor> processor;

    std::vector<uint8_t> matchesToGather;
    bool saveParamOnMatch { false };

    bool matchWithTransformer(const ddwaf_object* baseInput, MatchGatherer& gatherer, bool onKey, bool readOnlyArg) const;
    PWRULE_MATCH_STATUS _matchPastMatches(PWRetriever& retriever, const SQPowerWAF::monotonic_clock::time_point& deadline, PWRetManager& retManager) const;
    PWRULE_MATCH_STATUS _matchTargets(PWRetriever& retriever, const SQPowerWAF::monotonic_clock::time_point& deadline, PWRetManager& retManager) const;

public:
    PWRule(std::vector<PWManifest::ARG_ID>&& targets_,
           std::vector<PW_TRANSFORM_ID>&& transformers,
           std::unique_ptr<IPWRuleProcessor>&& processor_) : targets(std::move(targets_)),
                                                             transformation(std::move(transformers)),
                                                             processor(std::move(processor_)) {}
    PWRule(PWRule&&) = default;
    PWRule& operator=(PWRule&&) = default;

    PWRule(const PWRule&) = delete;
    PWRule& operator=(const PWRule&) = delete;
    PWRULE_MATCH_STATUS performMatching(PWRetriever& retriever, const SQPowerWAF::monotonic_clock::time_point& deadline, PWRetManager& retManager) const;

    bool doesUseNewParameters(const PWRetriever& retriever) const;
};

#endif /* PWRule_hpp */
