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
#include <utils.hpp>
#include <waf.hpp>

namespace ddwaf {

DDWAF_RET_CODE context::run(ddwaf_object &input, optional_ref<ddwaf_result> res, uint64_t timeout)
{
    if (res.has_value()) {
        ddwaf_result &output = *res;
        output = DDWAF_RESULT_INITIALISER;
    }

    if (!store_.insert(input, ruleset_->free_fn)) {
        DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
        return DDWAF_ERR_INVALID_OBJECT;
    }

    // If the timeout provided is 0, we need to ensure the parameters are owned
    // by the additive to ensure that the semantics of DDWAF_ERR_TIMEOUT are
    // consistent across all possible timeout scenarios.
    if (timeout == 0) {
        if (res.has_value()) {
            ddwaf_result &output = *res;
            output.timeout = true;
        }
        return DDWAF_OK;
    }

    ddwaf::timer deadline{std::chrono::microseconds(timeout)};

    // If this is a new run but no rule care about those new params, let's skip the run
    if (!is_first_run() && !store_.has_new_targets()) {
        return DDWAF_OK;
    }

    const event_serializer serializer(*ruleset_->event_obfuscator);

    optional_ref<ddwaf_object> derived;
    if (res.has_value()) {
        ddwaf_result &output = *res;
        ddwaf_object_map(&output.derivatives);
        derived.emplace(output.derivatives);
    }

    memory::vector<ddwaf::event> events;
    try {
        eval_preprocessors(derived, deadline);

        // If no rule targets are available, there is no point in evaluating them
        const auto &rules = rules_to_eval();
        if (!rules.empty() || should_eval_filters()) {
            // Filters need to be evaluated even if rules don't, otherwise it'll
            // break the current condition cache mechanism which requires knowing
            // if an address is new to this run.
            const auto &rules_to_exclude = filter_rules(deadline);
            const auto &objects_to_exclude = filter_inputs(rules_to_exclude, deadline);

            if (!rules.empty()) {
                events = match(rules, rules_to_exclude, objects_to_exclude, deadline);
            }
        }

        eval_postprocessors(derived, deadline);
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

const memory::unordered_map<rule *, filter_mode> &context::filter_rules(ddwaf::timer &deadline)
{
    DDWAF_DEBUG("Evaluating rule filters");

    for (const auto &[id, filter] : ruleset_->rule_filters) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating rule filters");
            throw timeout_exception();
        }

        auto it = rule_filter_cache_.find(filter.get());
        if (it == rule_filter_cache_.end()) {
            auto [new_it, res] =
                rule_filter_cache_.emplace(filter.get(), rule_filter::cache_type{});
            it = new_it;
        }

        rule_filter::cache_type &cache = it->second;
        auto exclusion = filter->match(store_, cache, deadline);
        if (exclusion.has_value()) {
            for (auto &&rule : exclusion->get()) {
                auto [it, res] = rules_to_exclude_.emplace(rule, filter->get_mode());
                // Bypass has precedence over monitor
                if (!res && it != rules_to_exclude_.end() && it->second != filter_mode::bypass) {
                    it->second = filter->get_mode();
                }
            }
        }
    }
    return rules_to_exclude_;
}

void context::eval_preprocessors(optional_ref<ddwaf_object> &derived, ddwaf::timer &deadline)
{
    DDWAF_DEBUG("Evaluating preprocessors");

    for (const auto &[id, preproc] : ruleset_->preprocessors) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating preprocessors");
            throw timeout_exception();
        }

        auto it = processor_cache_.find(preproc.get());
        if (it == processor_cache_.end()) {
            auto [new_it, res] = processor_cache_.emplace(preproc.get(), processor::cache_type{});
            it = new_it;
        }

        preproc->eval(store_, derived, it->second, deadline);
    }
}

void context::eval_postprocessors(optional_ref<ddwaf_object> &derived, ddwaf::timer &deadline)
{
    DDWAF_DEBUG("Evaluating postprocessors");

    for (const auto &[id, postproc] : ruleset_->postprocessors) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating postprocessors");
            throw timeout_exception();
        }

        auto it = processor_cache_.find(postproc.get());
        if (it == processor_cache_.end()) {
            auto [new_it, res] = processor_cache_.emplace(postproc.get(), processor::cache_type{});
            it = new_it;
        }

        postproc->eval(store_, derived, it->second, deadline);
    }
}

const memory::unordered_map<rule *, context::object_set> &context::filter_inputs(
    const memory::unordered_map<rule *, filter_mode> &rules_to_exclude, ddwaf::timer &deadline)
{
    DDWAF_DEBUG("Evaluating input filters");

    for (const auto &[id, filter] : ruleset_->input_filters) {
        if (deadline.expired()) {
            DDWAF_INFO("Ran out of time while evaluating input filters");
            throw timeout_exception();
        }

        auto it = input_filter_cache_.find(filter.get());
        if (it == input_filter_cache_.end()) {
            auto [new_it, res] =
                input_filter_cache_.emplace(filter.get(), input_filter::cache_type{});
            it = new_it;
        }

        input_filter::cache_type &cache = it->second;
        auto exclusion = filter->match(store_, cache, deadline);
        if (exclusion.has_value()) {
            for (const auto &rule : exclusion->rules) {
                auto exclude_it = rules_to_exclude.find(rule);
                if (exclude_it != rules_to_exclude.end() &&
                    exclude_it->second == filter_mode::bypass) {
                    continue;
                }

                auto &common_exclusion = objects_to_exclude_[rule];
                common_exclusion.insert(exclusion->objects.begin(), exclusion->objects.end());
            }
        }
    }

    return objects_to_exclude_;
}

const memory::set<rule *, rule::greater_than> &context::rules_to_eval()
{
    rules_.clear();

    const auto &targets = store_.get_latest_targets();
    for (auto target : targets) {
        auto it = ruleset_->rules_by_targets.find(target);
        if (it == ruleset_->rules_by_targets.end()) {
            continue;
        }

        const auto &target_rules = it->second;
        for (auto *rule : target_rules) { rules_.emplace(rule); }
    }

    return rules_;
}

memory::vector<event> context::match(const memory::set<rule *, rule::greater_than> &rules,
    const memory::unordered_map<rule *, filter_mode> &rules_to_exclude,
    const memory::unordered_map<rule *, object_set> &objects_to_exclude, ddwaf::timer &deadline)
{
    memory::vector<ddwaf::event> events;

    for (auto rule_it = rules.begin(); rule_it != rules.end();) {
        auto type = (*rule_it)->get_type();
        auto cache_it = collection_cache_.find(type);
        if (cache_it == collection_cache_.end()) {
            auto [new_it, res] = collection_cache_.emplace(type, collection_type::none);
            cache_it = new_it;
        }

        do {
            const auto &rule = *rule_it;

            auto level = rule->has_actions() ? collection_type::priority : collection_type::regular;
            if (cache_it->second >= level) {
                // Skip to next type
                while (++rule_it != rules.end() && (*rule_it)->get_type() == type) {}
                break;
            }

            if (deadline.expired()) {
                DDWAF_INFO("Ran out of time while evaluating rule '%s'", rule->get_id().c_str());
                throw timeout_exception();
            }

            bool skip_actions = false;
            auto exclude_it = rules_to_exclude.find(rule);
            if (exclude_it != rules_to_exclude.end()) {
                if (exclude_it->second == exclusion::filter_mode::bypass) {
                    DDWAF_DEBUG("Bypassing rule '%s'", rule->get_id().c_str());
                    continue;
                }

                DDWAF_DEBUG("Monitoring rule '%s'", rule->get_id().c_str());
                skip_actions = true;
            } else {
                DDWAF_DEBUG("Evaluating rule '%s'", rule->get_id().c_str());
            }

            try {
                auto it = rule_cache_.find(rule);
                if (it == rule_cache_.end()) {
                    auto [new_it, res] = rule_cache_.emplace(rule, rule::cache_type{});
                    it = new_it;
                }

                const auto &dynamic_matchers = ruleset_->dynamic_matchers;

                rule::cache_type &rule_cache = it->second;
                std::optional<event> event;
                auto exclude_it = objects_to_exclude.find(rule);
                if (exclude_it != objects_to_exclude.end()) {
                    const auto &objects_excluded = exclude_it->second;
                    event = rule->match(
                        store_, rule_cache, objects_excluded, dynamic_matchers, deadline);
                } else {
                    event = rule->match(store_, rule_cache, {}, dynamic_matchers, deadline);
                }

                if (event.has_value()) {
                    cache_it->second = level;
                    event->skip_actions = skip_actions;
                    events.emplace_back(std::move(*event));
                    DDWAF_DEBUG("Found event on rule %s", rule->get_id().c_str());

                    // Skip to next type
                    while (++rule_it != rules.end() && (*rule_it)->get_type() == type) {}
                    break;
                }
            } catch (const ddwaf::timeout_exception &) {
                DDWAF_INFO("Ran out of time while evaluating rule '%s'", rule->get_id().c_str());
                throw;
            }
        } while (++rule_it != rules.end() && (*rule_it)->get_type() == type);
    }

    return events;
}

} // namespace ddwaf
