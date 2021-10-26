// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PWProcessor.hpp>
#include <PWRet.hpp>
#include <ddwaf.h>
#include <iostream>
#include <log.hpp>

using status = ddwaf::condition::status;

PWProcessor::PWProcessor(PWRetriever& input, const ddwaf::rule_map& rules_)
    : parameters(input), rules(rules_), runCount(0)
{
    ranCache.reserve(rules.size());
    matchCache.reserve(16);
    document.SetArray();
}

void PWProcessor::startNewRun(const SQPowerWAF::monotonic_clock::time_point& _deadline)
{
    document.GetArray().Clear();
    deadline = _deadline;
    runCount += 1;
}

bool PWProcessor::hasCacheHit(const std::string& ruleID, bool& hadNegativeMatch, bool& hitFromThisRun) const
{
    const auto cacheHit    = ranCache.find(ruleID);
    const bool hasCacheHit = cacheHit != ranCache.end();
    if (hasCacheHit)
    {
        if (cacheHit->second.first)
        {
            return true;
        }

        hadNegativeMatch = true;
        hitFromThisRun   = cacheHit->second.second == runCount;
    }

    return false;
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
        retManager.recordResult(DDWAF_ERR_TIMEOUT);
        return;
    }

    bool didMatch = false, skippedRule = true;

    ddwaf::rule_map::const_iterator ruleMatched;

    retManager.startRule();

    //Process each rule we have to run for this step of the flow
    for (const std::string& ruleID : flow)
    {
        DDWAF_DEBUG("Running the WAF on rule %s", ruleID.c_str());

        //Have we already ran this rule?
        bool cachedNegativeMatch = false, hitFromThisRun = false;
        if (hasCacheHit(ruleID, cachedNegativeMatch, hitFromThisRun))
        {
            didMatch = false;
            break;
        }

        // Let's fetch the filters for the rule
        auto it = rules.find(ruleID);
        if (it == rules.end())
        {
            // This shouldn't happen
            DDWAF_ERROR("Invalid rule (%s) in flow (%s), this is a bug",
                        ruleID.c_str(), name.c_str());
            skippedRule = true;
            continue;
        }

        const ddwaf::rule& rule = it->second;
        didMatch                = false;

        // If we had a negative match in the past, let's check if we have a reason to run again
        if (cachedNegativeMatch && (hitFromThisRun || !shouldIgnoreCacheHit(rule.conditions)))
        {
            skippedRule = true;
            continue;
        }

        if (retManager.shouldRecordTime() && skippedRule)
        {
            past = SQPowerWAF::monotonic_clock::now();
        }

        // Actually execute the rule
        //	We tell the PWRetriever to skip old parameters if this is safe to do so
        parameters.resetMatchSession(cachedNegativeMatch && rule.conditions.size() == 1);

        size_t filter = 0;
        for (const ddwaf::condition& cond : rule.conditions)
        {
            parameters.setActiveFilter(filter++);
            status matchingStatus = cond.performMatching(parameters, deadline, retManager);

            //Stop if we didn't matched any of the parameters (2) or that the parameter couldn't be found
            if (matchingStatus == status::no_match || matchingStatus == status::missing_arg)
            {
                if (matchingStatus == status::missing_arg)
                    DDWAF_DEBUG("Missing arguments to run rule %s", ruleID.c_str());
                didMatch = false;
                break;
            }

            else if (matchingStatus == status::timeout)
            {
                DDWAF_INFO("Ran out of time when processing %s", ruleID.c_str());
                retManager.recordResult(DDWAF_ERR_TIMEOUT);
                return;
            }
            else
            {
                DDWAF_DEBUG("Matched rule %s", ruleID.c_str());
                didMatch = true;
            }
        }

        //Store the result of the rule in the cache
        if (cachedNegativeMatch)
        {
            // If we bypassed the cache, then we need to overwrite the entry
            ranCache.at(ruleID) = { didMatch, runCount };
        }
        else
        {
            // If that's the first execution, insert the cache entry
            ranCache.insert({ ruleID, { didMatch, runCount } });
        }

        // Collect the match payload
        if (didMatch)
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

        if (didMatch)
        {
            ruleMatched = it;
            break;
        }

        if (deadline <= now)
        {
            DDWAF_INFO("Ran out of time while running flow %s and rule %s", name.c_str(), ruleID.c_str());
            retManager.recordResult(DDWAF_ERR_TIMEOUT);
            return;
        }
    }

    // We don't want to report a trigger that only happened in the cache
    if (didMatch)
    {
        DDWAF_RET_CODE code = DDWAF_MONITOR;
        // This should always be the case but let's be carefull
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
