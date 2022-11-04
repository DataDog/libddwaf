// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <log.hpp>

#include <context.hpp>
#include <exception.hpp>
#include <tuple>
#include <utils.h>
#include <waf.hpp>

namespace ddwaf
{

DDWAF_RET_CODE context::run(const ddwaf_object &newParameters,
    optional_ref<ddwaf_result> res, uint64_t timeLeft)
{
    if (res.has_value()) {
        ddwaf_result& output = *res;
        output = {false, nullptr, {nullptr, 0}, 0};
    }

    if (!store_.insert(newParameters)) {
        DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
        return DDWAF_ERR_INVALID_OBJECT;
    }

    // If the timeout provided is 0, we need to ensure the parameters are owned
    // by the additive to ensure that the semantics of DDWAF_ERR_TIMEOUT are
    // consistent across all possible timeout scenarios.
    if (timeLeft == 0) {
        if (res.has_value()) {
            ddwaf_result& output = *res;
            output.timeout       = true;
        }
        return DDWAF_OK;
    }

    ddwaf::timer deadline{std::chrono::microseconds(timeLeft)};

    // If this is a new run but no rule care about those new params, let's skip the run
    if (!is_first_run() && !store_.has_new_targets()) {
        return DDWAF_OK;
    }

    event_serializer serializer(config_.event_obfuscator);

    // Get rule_ref array of rules to run on
    // Should the rules be ordered by collection?
    // FIXME currently generating a rule_ref vector from original set of rules

    auto rules = filter(deadline);
    if (!rules.empty()) {
        match(rules, serializer, deadline);
    }

    DDWAF_RET_CODE code = serializer.has_events() ? DDWAF_MATCH : DDWAF_OK;
    if (res.has_value()) {
        ddwaf_result& output = *res;
        serializer.serialize(output);
        output.total_runtime = deadline.elapsed().count();
        output.timeout = deadline.expired_before();
    }

    return code;
}

std::unordered_set<std::shared_ptr<rule>> context::filter(ddwaf::timer& deadline)
{
    std::unordered_set<std::shared_ptr<rule>> rules_to_exclude;
    for (const auto &filter : ruleset_.filters) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while running exclusion filters");
            return {};
        }

        bool result = false;
        auto it = filter_cache_.find(filter);
        if (it == filter_cache_.end()) {
            auto [new_it, res] = filter_cache_.emplace(filter, 
                    exclusion_filter::cache_type{});
            it = new_it;
        }

        exclusion_filter::cache_type &cache = it->second;
        if (!cache.result) {
            result = filter->match(store_, ruleset_.manifest,
                cache, deadline);
        } else {
            result = true;
        }

        if (result) {
            cache.result = true;
            for (auto rule: filter->get_rule_targets()) {
                rules_to_exclude.emplace(rule);
            }
        }
    }

    std::unordered_set<std::shared_ptr<rule>> rules_to_run;
    std::set_difference(ruleset_.rule_set.begin(), ruleset_.rule_set.end(),
        rules_to_exclude.begin(), rules_to_exclude.end(),
        std::inserter(rules_to_run, rules_to_run.begin()));

    return rules_to_run;
}

void context::match(const std::unordered_set<std::shared_ptr<rule>>& rules,
  event_serializer &serializer, ddwaf::timer& deadline)
{
    //Process each rule we have to run for this step of the collection
    for (auto rule : rules)
    {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while running rule %s", rule->id.c_str());
            break;
        }

        if (!rule->is_enabled()) { continue; }

        if (collection_cache_.find(rule->type) != collection_cache_.end()) {
            continue;
        }

        DDWAF_DEBUG("Running the WAF on rule %s", rule->id.c_str());

        try {
            auto it = rule_cache_.find(rule);
            if (it != rule_cache_.end() && it->second.result) {
                continue;
            } else {
                auto [new_it, res] = rule_cache_.emplace(rule, rule::cache_type{});
                it = new_it;
            }

            rule::cache_type &cache = it->second;
            auto event = rule->match(store_, ruleset_.manifest, cache, deadline);
            if (event.has_value()) {
                cache.result = true;
                collection_cache_.emplace(rule->type);
                serializer.insert(std::move(*event));
                DDWAF_DEBUG("Found event on rule %s", rule->id.c_str());
            }
        } catch (const ddwaf::timeout_exception&) {
            DDWAF_INFO("Ran out of time when processing %s", rule->id.c_str());
            break;
        }
    }
}

} // namespace ddwaf
