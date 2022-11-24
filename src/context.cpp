// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <log.hpp>

#include <context.hpp>
#include <exception.hpp>
#include <tuple>
#include <unordered_set>
#include <utils.h>
#include <waf.hpp>

namespace ddwaf {

DDWAF_RET_CODE context::run(
    const ddwaf_object &newParameters, optional_ref<ddwaf_result> res, uint64_t timeLeft)
{
    if (res.has_value()) {
        ddwaf_result &output = *res;
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
            ddwaf_result &output = *res;
            output.timeout = true;
        }
        return DDWAF_OK;
    }

    ddwaf::timer deadline{std::chrono::microseconds(timeLeft)};

    // If this is a new run but no rule care about those new params, let's skip the run
    if (!is_first_run() && !store_.has_new_targets()) {
        return DDWAF_OK;
    }

    const event_serializer serializer(config_.event_obfuscator);

    std::vector<ddwaf::event> events;
    try {
        // Get rule_ref array of rules to exclude.
        auto rules_to_exclude = filter(deadline);
        events = match(rules_to_exclude, deadline);
    } catch (const ddwaf::timeout_exception &) {}

    const DDWAF_RET_CODE code = events.empty() ? DDWAF_OK : DDWAF_MATCH;
    if (res.has_value()) {
        ddwaf_result &output = *res;
        serializer.serialize(events, output);
        output.total_runtime = deadline.elapsed().count();
        output.timeout = deadline.expired_before();
    }

    return code;
}

std::unordered_map<rule::ptr, context::exclusions> context::filter(ddwaf::timer &deadline)
{
    std::unordered_map<rule::ptr, exclusions> rules_to_exclude;
    for (const auto &filter : ruleset_.filters) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while running exclusion filters");
            throw timeout_exception();
        }

        auto it = filter_cache_.find(filter);
        if (it == filter_cache_.end()) {
            auto [new_it, res] = filter_cache_.emplace(filter, exclusion_filter::cache_type{});
            it = new_it;
        }

        exclusion_filter::cache_type &cache = it->second;
        auto exclusion = filter->match(store_, ruleset_.manifest, cache, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                auto &common_exclusion = rules_to_exclude[rule];
                for (const auto &input : exclusion->inputs) {
                    common_exclusion.inputs.insert(input);
                }
                for (auto *object : exclusion->objects) {
                    common_exclusion.objects.emplace(object);
                }
            }
        }
    }

    return rules_to_exclude;
}

std::vector<event> context::match(const std::unordered_map<rule::ptr, exclusions> &exclude,
    ddwaf::timer &deadline)
{
    // Process each rule we have to run for this step of the collection
    std::vector<ddwaf::event> events;
    for (auto &[type, collection] : ruleset_.collections) {
        if (collection_cache_.find(type) != collection_cache_.end()) {
            continue;
        }

        for (const auto &rule : collection) {
            const auto &id = rule->id;

            if (deadline.expired()) {
                DDWAF_INFO("Ran out of time while running rule %s", id.c_str());
                throw timeout_exception();
            }

            if (!rule->is_enabled()) {
                continue;
            }

            auto exclude_it = exclude.find(rule);
            if (exclude_it != exclude.end() && exclude_it->second.exclude_rule()) {
                DDWAF_DEBUG("Excluding Rule %s", id.c_str());
                continue;
            }

            DDWAF_DEBUG("Running the WAF on rule %s", id.c_str());

            try {
                auto it = rule_cache_.find(rule);
                if (it == rule_cache_.end()) {
                    auto [new_it, res] = rule_cache_.emplace(rule, rule::cache_type{});
                    it = new_it;
                }

                rule::cache_type &cache = it->second;
                std::optional<event> event;
                if (exclude_it != exclude.end()) {
                    const auto &[inputs_excluded, objects_excluded] = exclude_it->second;
                    event = rule->match(store_, ruleset_.manifest, cache,
                            inputs_excluded, objects_excluded, deadline);
                } else {
                    event = rule->match(store_, ruleset_.manifest, cache, {}, {}, deadline);
                }

                if (event.has_value()) {
                    collection_cache_.emplace(rule->type);
                    events.emplace_back(std::move(*event));
                    DDWAF_DEBUG("Found event on rule %s", id.c_str());
                    break;
                }
            } catch (const ddwaf::timeout_exception &) {
                DDWAF_INFO("Ran out of time while processing %s", id.c_str());
                throw;
            }
        }
    }

    return events;
}

} // namespace ddwaf
