// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule.hpp>

#include <IPWRuleProcessor.h>
#include <waf.hpp>

#include "clock.hpp"
#include <log.hpp>

#include <iostream>

namespace ddwaf
{

bool condition::matchWithTransformer(const ddwaf_object* baseInput, 
  MatchGatherer& gatherer) const
{
    const bool hasTransformation        = !transformation.empty();
    bool transformationWillChangeString = false;

    if (baseInput->type != DDWAF_OBJ_STRING) {
        return processor->doesMatch(baseInput, gatherer);
    }

    if (hasTransformation)
    {
        // This codepath is shared with the mutable path. The structure can't be const :/
        transformationWillChangeString = PWTransformer::doesNeedTransform(transformation,
            const_cast<ddwaf_object *>(baseInput));
    }

    size_t length = find_string_cutoff(baseInput->stringValue,
            baseInput->nbEntries, limits_.max_string_length);

    //If we don't have transformation to perform, or if they're irrelevant, no need to waste time copying and allocating data
    if (!hasTransformation || !transformationWillChangeString)
    {
        ddwaf_object input;
        ddwaf_object_stringl_nc(&input, baseInput->stringValue, length);

        return processor->doesMatch(&input, gatherer);
    }

    ddwaf_object copyInput;
    ddwaf_object_stringl(&copyInput, (const char*) baseInput->stringValue, length);

    //Transform it and pick the pointer to process
    bool transformFailed = false, matched = false;
    for (const PW_TRANSFORM_ID& transform : transformation)
    {
        transformFailed = !PWTransformer::transform(transform, &copyInput);
        if (transformFailed || (copyInput.type == DDWAF_OBJ_STRING && copyInput.nbEntries == 0))
        {
            break;
        }
    }

    //Run the transformed input
    if (transformFailed) {
        ddwaf_object input;
        ddwaf_object_stringl_nc(&input, baseInput->stringValue, length);

        matched |= processor->doesMatch(&input, gatherer);
    } else {
        matched |= processor->doesMatch(&copyInput, gatherer);
    }

    // Otherwise, the caller is in charge of freeing the pointer
    ddwaf_object_free(&copyInput);

    return matched;
}

template <typename T>
condition::status condition::match_target(T &it,
    const std::string &name,
    const monotonic_clock::time_point& deadline,
    PWRetManager& retManager) const
{
    size_t counter = 0;

    for (; it; ++it) {
        // Only check the time every 16 runs
        // TODO abstract away deadline checks into custom object
        if ((++counter & 0xf) == 0 && deadline <= monotonic_clock::now())
        {
            return status::timeout;
        }

        MatchGatherer gather;
        if ((it.type() & processor->expectedTypes()) == 0) { continue; }
        if (!matchWithTransformer(*it, gather)) { continue; }

        gather.keyPath = it.get_current_path();
        gather.dataSource = name;

        DDWAF_TRACE("Target %s matched %s out of parameter value %s",
                    gather.dataSource.c_str(),
                    gather.matchedValue.c_str(),
                    gather.resolvedValue.c_str());

        retManager.recordRuleMatch(processor, gather);

        //If this target matched, we can stop processing
        return status::matched;
    }

    return status::no_match;
}

condition::status condition::performMatching(object_store& store,
    const ddwaf::manifest &manifest, bool run_on_new,
    const monotonic_clock::time_point& deadline,
    PWRetManager& retManager) const
{
    for (const auto &target : targets) {

        // TODO: the conditions should keep track of the targets already
        // checked.
        if (run_on_new && !store.is_new_target(target)) {
            continue;
        }

        const auto& info = manifest.get_target_info(target);

        // TODO: iterators could be cached to avoid reinitialisation

        condition::status res = status::no_match;
        auto object = store.get_target(target);
        if (object == nullptr) { continue; }

        if (source_ == data_source::keys) {
            object::key_iterator it(object, info.key_path, limits_);
            res = match_target(it, info.name, deadline, retManager);
        } else {
            object::value_iterator it(object, info.key_path, limits_);
            res = match_target(it, info.name, deadline, retManager);
        }

        if (res == status::matched) { return status::matched; }
    }

    // Only @exist care about this branch, it's at the end to enable a better report when there is a real value
    if (processor->matchAnyInput())
    {
        retManager.recordRuleMatch(processor, MatchGatherer());
        return status::matched;
    }

    //	If at least one resolved, but didn't matched, we return NO_MATCH
    return status::no_match;
}

bool condition::has_new_targets(const object_store& store) const
{
    for (const auto& target : targets)
    {
        if (store.is_new_target(target)) {
            return true;
        }
    }

    return false;
}

bool rule::has_new_targets(const object_store &store) const
{
    for (const auto& cond : conditions)
    {
        if (cond.has_new_targets(store)) {
            return true;
        }
    }

    return false;
}

}
