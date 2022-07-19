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
#include <iterator.hpp>
#include <manifest.hpp>
#include <PWRet.hpp>
#include <object_store.hpp>
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

    enum class data_source : uint8_t
    {
        values,
        keys
    };

    condition(std::vector<ddwaf::manifest::target_type>&& targets_,
              std::vector<PW_TRANSFORM_ID>&& transformers,
              std::unique_ptr<IPWRuleProcessor>&& processor_,
              data_source source = data_source::values):
        targets(std::move(targets_)),
        transformation(std::move(transformers)),
        processor(std::move(processor_)),
        source_(source) {}

    condition(condition&&) = default;
    condition& operator=(condition&&) = default;

    condition(const condition&) = delete;
    condition& operator=(const condition&) = delete;

    status performMatching(object_store& store,
        const ddwaf::manifest &manifest, bool run_on_new,
        const monotonic_clock::time_point& deadline,
        PWRetManager& retManager) const;

    bool matchWithTransformer(const ddwaf_object* baseInput, MatchGatherer& gatherer) const;
    bool doesUseNewParameters(const object_store& store) const;

protected:
    template <typename T>
    status match_target(T &it,
        const std::string &name,
        const monotonic_clock::time_point& deadline,
        PWRetManager& retManager) const;

    std::vector<ddwaf::manifest::target_type> targets;
    std::vector<PW_TRANSFORM_ID> transformation;
    std::unique_ptr<IPWRuleProcessor> processor;
    data_source source_;
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
