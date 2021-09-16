// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <PWProcessor.hpp>
#include <PWRet.hpp>
#include <ddwaf.h>

#include <log.hpp>

PWProcessor::PWProcessor(PWRetriever& input, const PWRuleManager& rManager)
    : parameters(input), ruleManager(rManager), runCount(0)
{
    ranCache.reserve(rManager.getNbRules());
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

bool PWProcessor::shouldIgnoreCacheHit(const std::vector<PWRule>& rules) const
{
    for (const PWRule& rule : rules)
    {
        if (rule.doesUseNewParameters(parameters))
        {
            // Yep, let's ignore the previous negative match
            return true;
        }
    }

    return false;
}

void PWProcessor::runFlow(const std::string& name, const std::vector<std::string>& flow, PWRetManager& retManager)
{
    bool didMatchPastCache                       = false;
    SQPowerWAF::monotonic_clock::time_point past = SQPowerWAF::monotonic_clock::now();
    SQPowerWAF::monotonic_clock::time_point now  = past;
    /*
	 *	A flow is a sequence of steps
	 *	Each step provide an array of ruleIDs to match. The rule match if any of those rules matched (1)
	 *	Each ruleID provide an array of filters (PWRule) and must all be matched for the rule to be matched (2)
	 */
    DDWAF_DEBUG("Running flow %s", name.c_str());

    //If we ran out of time, we want to generate DDWAF_ERR_TIMEOUT records for every flow we're going to skip
    //This also protect us against loops for free (the cache could avoid the inner loop's check)
    if (deadline <= now)
    {
        DDWAF_INFO("Ran out of time while running flow %s", name.c_str());
        return retManager.commitResult(DDWAF_ERR_TIMEOUT, name);
    }

    bool didMatch = false, skippedRule = true;
    std::string ruleMatched;

    retManager.startRule();

    //Process each rule we have to run for this step of the flow
    for (const std::string& ruleID : flow)
    {
        DDWAF_DEBUG("Running the WAF on rule %s", ruleID.c_str());

        //Have we already ran this rule?
        bool cachedNegativeMatch = false, hitFromThisRun = false;
        if (hasCacheHit(ruleID, cachedNegativeMatch, hitFromThisRun))
        {
            didMatch    = true;
            ruleMatched = ruleID;
            break;
        }

        // Let's fetch the filters for the rule
        const std::vector<PWRule>& rules = ruleManager.getRules(ruleID);
        didMatch                         = false;

        // If we had a negative match in the past, let's check if we have a reason to run again
        if (cachedNegativeMatch && (hitFromThisRun || !shouldIgnoreCacheHit(rules)))
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
        parameters.resetMatchSession(cachedNegativeMatch && rules.size() == 1);

        size_t filter = 0;
        for (const PWRule& rule : rules)
        {
            parameters.setActiveFilter(filter++);
            PWRULE_MATCH_STATUS matchingStatus = rule.performMatching(parameters, deadline, retManager);

            //Stop if we didn't matched any of the parameters (2) or that the parameter couldn't be found
            if (matchingStatus == NO_MATCH || matchingStatus == MISSING_ARG)
            {
                if (matchingStatus == MISSING_ARG)
                    DDWAF_DEBUG("Missing arguments to run rule %s", ruleID.c_str());
                didMatch = false;
                break;
            }

            else if (matchingStatus == TIMEOUT)
            {
                DDWAF_INFO("Ran out of time when processing %s", ruleID.c_str());
                return retManager.commitResult(DDWAF_ERR_TIMEOUT, name);
            }
            else
            {
                DDWAF_DEBUG("Matched rule %s", ruleID.c_str());
                didMatchPastCache = didMatch = true;
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
            ruleMatched = ruleID;
            break;
        }

        if (deadline <= now)
        {
            DDWAF_INFO("Ran out of time while running flow %s and rule %s", name.c_str(), ruleID.c_str());
            retManager.commitResult(DDWAF_ERR_TIMEOUT, name);
            return;
        }
    }

    // We don't want to report a trigger that only happened in the cache
    if (didMatch)
    {
        if (didMatchPastCache)
        {
            DDWAF_RET_CODE code = DDWAF_MONITOR;
            // This should always be the case but let's be carefull
            const auto& match = matchCache.find(ruleMatched);
            if (match != matchCache.end())
            {
                retManager.reportMatch(code, name, ruleMatched, match->second);
            }

            retManager.recordResult(code);
        }
        else
        {
            retManager.removeResultFlow(name);
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
