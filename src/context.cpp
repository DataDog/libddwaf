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

    auto rules = prefilter.filter(store_, deadline);
    run_rules(rules, serializer, deadline);

    DDWAF_RET_CODE code = serializer.has_events() ? DDWAF_MATCH : DDWAF_OK;
    if (res.has_value()) {
        ddwaf_result& output = *res;
        serializer.serialize(output);
        output.total_runtime = deadline.elapsed().count();
        output.timeout = deadline.expired_before();
    }

    return code;
}

bool context::run_rules(const ddwaf::rule_ref_vector& rules,
  event_serializer &serializer, ddwaf::timer& deadline)
{
    //Process each rule we have to run for this step of the collection
    for (ddwaf::rule& rule : rules)
    {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while running rule %s", rule.id.c_str());
            break;
        }

        if (!rule.is_enabled()) { continue; }

        if (collection_cache_.find(rule.type) != collection_cache_.end()) {
            continue;
        }

        // TODO: replace this part with:
        //         - Rule cache containing individual condition matches, this
        //           cache will then allow the rule to keep track of which
        //           conditions have been executed.
        bool run_on_new = false;
        const auto hit = status_cache_.find(rule.index);
        if (hit != status_cache_.cend()) {
            // There was a match cached for this rule, stop processing collection
            if (hit->second) { continue; }

            // The value is present and it's false (no match), check if we have
            // new targets to decide if we should retry the rule.
            if (!rule.has_new_targets(store_)) { continue; }

            // Currently we are not keeping track of which conditions were executed
            // against the available data, so if a rule has more than one condition
            // we can't know which one caused the negative match and consequently
            // we don't know which ones have been executed.
            //
            // However if the rule only has one condition and there is a negative
            // match in the cache, we can safely assume it has already been executed
            // with existing data.
            run_on_new = (rule.conditions.size() == 1);
        }

        DDWAF_DEBUG("Running the WAF on rule %s", rule.id.c_str());

        try {
            auto event = rule.match(store_, ruleset_.manifest, run_on_new, deadline);

            status_cache_.insert_or_assign(rule.index, event.has_value());

            if (event.has_value()) {
                collection_cache_.emplace(rule.type);
                serializer.insert(std::move(*event));
                DDWAF_DEBUG("Found event on rule %s", rule.id.c_str());
            }
        } catch (const ddwaf::timeout_exception&) {
            DDWAF_INFO("Ran out of time when processing %s", rule.id.c_str());
            return false;
        }
    }

    return true;
}

} // namespace ddwaf
