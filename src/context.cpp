// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <log.hpp>

#include <context.hpp>
#include <PWRet.hpp>
#include <tuple>
#include <utils.h>
#include <waf.hpp>

using match_status = ddwaf::condition::status;

namespace ddwaf
{

DDWAF_RET_CODE context::run(ddwaf_object newParameters,
                               optional_ref<ddwaf_result> res, uint64_t timeLeft)
{
    if (!store_.insert(newParameters)) {
        DDWAF_WARN("Illegal WAF call: parameter structure invalid!");
        return DDWAF_ERR_INVALID_OBJECT;
    }

    // If the timeout provided is 0, we need to ensure the parameters are owned
    // by the additive to ensure that the semantics of DDWAF_ERR_TIMEOUT are
    // consistent across all possible timeout scenarios.
    if (timeLeft == 0)
    {
        if (res.has_value())
        {
            ddwaf_result& output = *res;
            output.timeout       = true;
        }
        return DDWAF_GOOD;
    }

    const auto start    = ddwaf::monotonic_clock::now();
    ddwaf::timer deadline{std::chrono::microseconds(timeLeft)};

    // If this is a new run but no rule care about those new params, let's skip the run
    if (!is_first_run() && !store_.has_new_targets())
    {
        return DDWAF_GOOD;
    }

    PWRetManager retManager(config_.event_obfuscator);
    for (const auto& [key, collection] : ruleset_.collections)
    {
        if (!run_collection(key, collection, retManager, deadline))
        {
            break;
        }
    }

    DDWAF_RET_CODE code = retManager.getResult();
    if (res.has_value())
    {
        ddwaf_result& output = *res;
        retManager.synthetize(output);
        output.total_runtime = (ddwaf::monotonic_clock::now() - start).count();
    }

    return code;
}

bool context::run_collection(const std::string& name,
  const ddwaf::rule_ref_vector& collection,
  PWRetManager& retManager, ddwaf::timer& deadline)
{
    /*
	 *	A collection is a sequence of steps
	 *	Each step provide an array of ruleIDs to match. The rule match if any of those rules matched (1)
	 *	Each ruleID provide an array of filters (condition) and must all be matched for the rule to be matched (2)
	 */
    DDWAF_DEBUG("Running collection %s", name.c_str());

    //If we ran out of time, we want to generate DDWAF_ERR_TIMEOUT records for every collection we're going to skip
    //This also protect us against loops for free (the cache could avoid the inner loop's check)
    if (deadline.expired())
    {
        DDWAF_INFO("Ran out of time while running collection %s", name.c_str());
        retManager.recordTimeout();
        return false;
    }

    match_status status = match_status::invalid;
    //Process each rule we have to run for this step of the collection
    for (ddwaf::rule& rule : collection)
    {
        status = match_status::invalid;

        //Have we already ran this rule?
        auto index              = rule.index;
        const auto cache_status = get_cached_status(index);
        if (cache_status == match_status::matched)
        {
            break;
        }

        DDWAF_DEBUG("Running the WAF on rule %s", rule.id.c_str());

        bool cachedNegativeMatch = cache_status == match_status::no_match;

        // If we had a negative match in the past, let's check if we have a reason to run again
        if (cachedNegativeMatch && !rule.has_new_targets(store_))
        {
            continue;
        }

        retManager.startRule();

        // Currently we are not keeping track of which conditions were executed
        // against the available data, so if a rule has more than one condition
        // we can't know which one caused the negative match and consequently
        // we don't know which ones have been executed.
        //
        // However if the rule only has one condition and there is a negative
        // match in the cache, we can safely assume it has already been executed
        // with existing data.
        bool run_on_new = cachedNegativeMatch && rule.conditions.size() == 1;
        for (const ddwaf::condition& cond : rule.conditions)
        {
            status = cond.match(store_, ruleset_.manifest, run_on_new, deadline, retManager);
            //Stop if we didn't matched any of the parameters (2) or that the parameter couldn't be found
            if (status == match_status::no_match)
            {
                break;
            }
            else if (status == match_status::missing_arg)
            {
                DDWAF_DEBUG("Missing arguments to run rule %s", rule.id.c_str());
                break;
            }
            else if (status == match_status::timeout)
            {
                DDWAF_INFO("Ran out of time when processing %s", rule.id.c_str());
                retManager.recordTimeout();
                return false;
            }
            else
            {
                DDWAF_DEBUG("Matched rule %s", rule.id.c_str());
            }
        }

        //Store the result of the rule in the cache
        if (status != match_status::missing_arg)
        {
            status_cache_.insert_or_assign(index, status);
        }

        // Update the time measurement, and check the deadline while we're at it
        // This is actually fairly important because the inner loop will only check after 16 iterations
        if (status == match_status::matched)
        {
            DDWAF_RET_CODE code = DDWAF_MONITOR;
            retManager.reportMatch(rule.id, name, rule.category, rule.name,
                                   retManager.fetchRuleCollector().GetArray());
            retManager.recordResult(code);
            break;
        }

        if (deadline.expired())
        {
            DDWAF_INFO("Ran out of time while running collection %s and rule %s", name.c_str(), rule.id.c_str());
            retManager.recordTimeout();
            return false;
        }
    }

    return true;
}


condition::status context::get_cached_status(ddwaf::rule::index_type rule_idx) const
{
    const auto hit = status_cache_.find(rule_idx);
    if (hit != status_cache_.end())
    {
        return hit->second;
    }

    return match_status::invalid;

}

}
