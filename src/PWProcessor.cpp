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
    matchCache.reserve(16);
    document.SetArray();
}

void PWProcessor::startNewRun(const SQPowerWAF::monotonic_clock::time_point& _deadline)
{
    document.GetArray().Clear();
    deadline = _deadline;
}

match_status PWProcessor::hasCacheHit(const std::string& ruleID) const
{
    const auto cacheHit = ranCache.find(ruleID);
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

void PWProcessor::runFlow(const std::string& name, const std::vector<std::string>& flow, PWRetManager& retManager)
{
    SQPowerWAF::monotonic_clock::time_point past = SQPowerWAF::monotonic_clock::now();
    SQPowerWAF::monotonic_clock::time_point now  = past;
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

    match_status status;
    ddwaf::rule_map::const_iterator ruleMatched;

    //Process each rule we have to run for this step of the flow
    for (const std::string& ruleID : flow)
    {
        DDWAF_DEBUG("Running the WAF on rule %s", ruleID.c_str());

        status = match_status::invalid;
        retManager.startRule();

        //Have we already ran this rule?
        const auto cache_status = hasCacheHit(ruleID);
        if (cache_status == match_status::matched) { break; }

        // Let's fetch the filters for the rule
        auto it = rules.find(ruleID);
        if (it == rules.end())
        {
            // This shouldn't happen
            DDWAF_ERROR("Invalid rule (%s) in flow (%s), this is a bug",
                        ruleID.c_str(), name.c_str());
            continue;
        }

        const ddwaf::rule& rule = it->second;

        bool cachedNegativeMatch = cache_status == match_status::no_match;

        // If we had a negative match in the past, let's check if we have a reason to run again
        if (cachedNegativeMatch && !shouldIgnoreCacheHit(rule.conditions))
        {
            continue;
        }

        if (retManager.shouldRecordTime())
        {
            past = SQPowerWAF::monotonic_clock::now();
        }

        // Actually execute the rule
        //	We tell the PWRetriever to skip old parameters if this is safe to do so
        parameters.resetMatchSession(cachedNegativeMatch && rule.conditions.size() == 1);

        for (const ddwaf::condition& cond : rule.conditions)
        {
            status = cond.performMatching(parameters, deadline, retManager);
            //Stop if we didn't matched any of the parameters (2) or that the parameter couldn't be found
            if (status == match_status::no_match) {
                break;
            } else if (status == match_status::missing_arg) {
                DDWAF_DEBUG("Missing arguments to run rule %s", ruleID.c_str());
                break;
            } else if (status == match_status::timeout) {
                DDWAF_INFO("Ran out of time when processing %s", ruleID.c_str());
                retManager.recordTimeout();
                return;
            } else {
                DDWAF_DEBUG("Matched rule %s", ruleID.c_str());
            }
        }

        //Store the result of the rule in the cache
        if (status != match_status::missing_arg) {
            ranCache.insert_or_assign(ruleID, status);
        }

        // Collect the match payload
        if (status == match_status::matched)
        {
            auto pair = std::pair<std::string, rapidjson::Value>(ruleID, retManager.fetchRuleCollector().GetArray());
            matchCache.insert(std::move(pair));
        }

        // Update the time measurement, and check the deadline while we're at it
        // This is actually fairly important because the inner loop will only check after 16 iterations
        now = SQPowerWAF::monotonic_clock::now();
        if (retManager.shouldRecordTime())
        {
            retManager.recordTime(ruleID, now - past);
            past = now;
        }

        if (status == match_status::matched)
        {
            ruleMatched = it;
            break;
        }

        if (deadline <= now)
        {
            DDWAF_INFO("Ran out of time while running flow %s and rule %s", name.c_str(), ruleID.c_str());
            retManager.recordTimeout();
            return;
        }
    }

    // We don't want to report a trigger that only happened in the cache
    if (status == match_status::matched)
    {
        DDWAF_RET_CODE code = DDWAF_MONITOR;
        // This should always be the case but let's be careful
        const auto& match = matchCache.find(ruleMatched->first);
        if (match != matchCache.end())
        {
            retManager.reportMatch(ruleMatched->first, name,
                                   ruleMatched->second.category, ruleMatched->second.name, match->second);
        }
        retManager.recordResult(code);
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
