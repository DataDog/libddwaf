// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>

#include <ddwaf.h>
#include <event.hpp>
#include <optional>
#include <rule.hpp>
#include <config.hpp>
#include <utils.h>
#include <obfuscator.hpp>
#include <rule_prefilter.hpp>
#include <ruleset.hpp>

namespace ddwaf
{

class context
{
public:
    context(ddwaf::ruleset &ruleset, const ddwaf::config &config):
        ruleset_(ruleset), config_(config),
        store_(ruleset_.manifest, config_.free_fn),
        prefilter(ruleset)
    {
        status_cache_.reserve(ruleset_.rules.size());
    }

    context(const context&) = delete;
    context& operator=(const context&) = delete;
    context(context&&) = default;
    context& operator=(context&&) = delete;
    ~context() = default;

    DDWAF_RET_CODE run(const ddwaf_object&, optional_ref<ddwaf_result> res, uint64_t);

protected:
    bool run_rules(const ddwaf::rule_ref_vector& rules,
        event_serializer& serializer,
        ddwaf::timer& deadline);

    bool is_first_run() const { return status_cache_.empty(); }

    ddwaf::ruleset &ruleset_;
    const ddwaf::config &config_;
    ddwaf::object_store store_;
    ddwaf::rule_prefilter prefilter;

    // Cache collections to avoid processing once a result has been obtained
    // TODO: strings should be replaced by a scalar.
    std::unordered_set<std::string> collection_cache_;

    // If we have seen a match, the value will be true, if the value is present
    // and false it means we executed the rule and it did not match.
    std::unordered_map<rule::index_type, bool> status_cache_;
};

}
