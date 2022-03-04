// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <IPWRuleProcessor.h>
#include <PWManifest.h>
#include <PWRet.hpp>
#include <PWRetriever.hpp>
#include <PWTransformer.h>
#include <clock.hpp>

namespace ddwaf
{

class condition
{
public:
    enum class status : uint8_t
    {
        missing_arg,
        timeout,
        invalid,
        matched,
        no_match
    };

public:
    condition(std::vector<PWManifest::ARG_ID>&& targets_,
              std::vector<PW_TRANSFORM_ID>&& transformers,
              std::unique_ptr<IPWRuleProcessor>&& processor_) : targets(std::move(targets_)),
                                                                transformation(std::move(transformers)),
                                                                processor(std::move(processor_)) {}
    condition(condition&&) = default;
    condition& operator=(condition&&) = default;

    condition(const condition&) = delete;
    condition& operator=(const condition&) = delete;
    status performMatching(PWRetriever& retriever, const ddwaf::monotonic_clock::time_point& deadline, PWRetManager& retManager) const;
    bool matchWithTransformer(const ddwaf_object* baseInput, MatchGatherer& gatherer, bool onKey, bool readOnlyArg) const;
    bool doesUseNewParameters(const PWRetriever& retriever) const;

protected:
    status _matchPastMatches(PWRetriever& retriever, const ddwaf::monotonic_clock::time_point& deadline, PWRetManager& retManager) const;
    status _matchTargets(PWRetriever& retriever, const ddwaf::monotonic_clock::time_point& deadline, PWRetManager& retManager) const;

    bool initialized;
    std::vector<PWManifest::ARG_ID> targets;
    std::vector<PW_TRANSFORM_ID> transformation;
    std::unique_ptr<IPWRuleProcessor> processor;
};

class rule
{
public:
    using index_type = uint32_t;

    index_type index;
    std::string id;
    std::string name;
    std::string category;
    std::vector<condition> conditions;
};

using rule_map        = std::unordered_map<rule::index_type, rule>;
using rule_vector     = std::vector<rule>;
using rule_ref_vector = std::vector<std::reference_wrapper<rule>>;
using flow_map        = std::unordered_map<std::string, rule_ref_vector>;

}
