// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PWProcessor.hpp>
#include <PWRet.hpp>
#include <ddwaf.h>
#include <log.hpp>

using match_status = ddwaf::condition::status;

PWProcessor::PWProcessor(PWRetriever& input, const ddwaf::rule_map& rules_)
    : parameters(input), rules(rules_)
{
    ranCache.reserve(rules.size());
    document.SetArray();
}

void PWProcessor::startNewRun(const ddwaf::monotonic_clock::time_point& _deadline)
{
    document.GetArray().Clear();
    deadline = _deadline;
}

match_status PWProcessor::hasCacheHit(ddwaf::rule::index_type rule_idx) const
{
    const auto cacheHit = ranCache.find(rule_idx);
    if (cacheHit != ranCache.end())
    {
        return cacheHit->second;
    }

    return match_status::invalid;
}

bool PWProcessor::shouldIgnoreCacheHit(const std::vector<ddwaf::condition>& conditions) const
{
    for (const ddwaf::condition& cond : conditions)
    {
        if (cond.doesUseNewParameters(parameters))
        {
            // Yep, let's ignore the previous negative match
            return true;
        }
    }

    return false;
}

void PWProcessor::runFlow(const std::string& name, 
                          const ddwaf::rule_ref_vector& flow,
                          ddwaf::metrics_collector &collector,
                          PWRetManager& retManager)
{
    ddwaf::monotonic_clock::time_point past = ddwaf::monotonic_clock::now();
    ddwaf::monotonic_clock::time_point now  = past;
    /*
	 *	A flow is a sequence of steps
	 *	Each step provide an array of ruleIDs to match. The rule match if any of those rules matched (1)
	 *	Each ruleID provide an array of filters (condition) and must all be matched for the rule to be matched (2)
	 */
    DDWAF_DEBUG("Running flow %s", name.c_str());

    //If we ran out of time, we want to generate DDWAF_ERR_TIMEOUT records for every flow we're going to skip
    //This also protect us against loops for free (the cache could avoid the inner loop's check)
    if (deadline <= now)
    {
        DDWAF_INFO("Ran out of time while running flow %s", name.c_str());
        retManager.recordTimeout();
        return;
    }

    match_status status = match_status::invalid;
    //Process each rule we have to run for this step of the flow
    for (ddwaf::rule &rule : flow)
    {
        status = match_status::invalid;

        //Have we already ran this rule?
        auto index = rule.index;
        const auto cache_status = hasCacheHit(index);
        if (cache_status == match_status::matched)
        {
            break;
        }

        DDWAF_DEBUG("Running the WAF on rule %s", rule.id.c_str());

        retManager.startRule();

        bool cachedNegativeMatch = cache_status == match_status::no_match;

        // If we had a negative match in the past, let's check if we have a reason to run again
        if (cachedNegativeMatch && !shouldIgnoreCacheHit(rule.conditions))
        {
            continue;
        }

        past = ddwaf::monotonic_clock::now();

        // Actually execute the rule
        //	We tell the PWRetriever to skip old parameters if this is safe to do so
        parameters.resetMatchSession(cachedNegativeMatch && rule.conditions.size() == 1);

        for (const ddwaf::condition& cond : rule.conditions)
        {
            status = cond.performMatching(parameters, deadline, retManager);
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
                return;
            }
            else
            {
                DDWAF_DEBUG("Matched rule %s", rule.id.c_str());
            }
        }

        now = ddwaf::monotonic_clock::now();
        //Store the result of the rule in the cache
        if (status != match_status::missing_arg)
        {
            ranCache.insert_or_assign(index, status);
        } 
        // Update the time measurement, and check the deadline while we're at it
        // This is actually fairly important because the inner loop will only check after 16 iterations
        else if (status == match_status::matched)
        {
            collector.record_rule(index, now - past);

            DDWAF_RET_CODE code = DDWAF_MONITOR;
            retManager.reportMatch(rule.id, name, rule.category, rule.name, 
                                   retManager.fetchRuleCollector().GetArray());
            retManager.recordResult(code);
            break;
        }
        else if (status == match_status::no_match)
        {
            collector.record_rule(index, now - past);
        }

        if (deadline <= now)
        {
            DDWAF_INFO("Ran out of time while running flow %s and rule %s", name.c_str(), rule.id.c_str());
            retManager.recordTimeout();
            return;
        }
    }
}

bool PWProcessor::isFirstRun() const
{
    return ranCache.empty();
}

rapidjson::Document::AllocatorType& PWProcessor::getGlobalAllocator()
{
    return document.GetAllocator();
}
