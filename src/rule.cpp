// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule.hpp>

#include <IPWRuleProcessor.h>
#include <PowerWAF.hpp>

#include "clock.hpp"
#include <log.hpp>

namespace ddwaf
{

bool condition::matchWithTransformer(const ddwaf_object* baseInput, MatchGatherer& gatherer) const
{
    const bool hasTransformation        = !transformation.empty();
    const bool canRunTransformation     = baseInput->type == DDWAF_OBJ_STRING;
    bool transformationWillChangeString = false;

    if (hasTransformation && canRunTransformation)
    {
        // This codepath is shared with the mutable path. The structure can't be const :/
        transformationWillChangeString = PWTransformer::doesNeedTransform(transformation,
            const_cast<ddwaf_object *>(baseInput));
    }

    //If we don't have transformation to perform, or if they're irrelevant, no need to waste time copying and allocating data
    if (!hasTransformation || !canRunTransformation || !transformationWillChangeString)
    {
        return processor->doesMatch(baseInput, gatherer);
    }

    ddwaf_object copyInput;
    ddwaf_object_stringl(&copyInput, (const char*) baseInput->stringValue, baseInput->nbEntries);

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
    const ddwaf_object* paramToUse = transformFailed ? baseInput : &copyInput;
    matched |= processor->doesMatch(paramToUse, gatherer);

    // Otherwise, the caller is in charge of freeing the pointer
    ddwaf_object_free(&copyInput);

    return matched;
}

template <typename T>
condition::status condition::match_target(T &it,
    const ddwaf::manifest &manifest,
    const ddwaf::manifest::target_info &info,
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
        gather.dataSource = manifest.get_target_name(info.root);

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
            object::key_iterator it(object, info.key_path);
            res = match_target(it, manifest, info, deadline, retManager);
        } else {
            object::value_iterator it(object, info.key_path);
            res = match_target(it, manifest, info, deadline, retManager);
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

bool condition::doesUseNewParameters(const object_store& store) const
{
    for (const ddwaf::manifest::target_type& target : targets)
    {
        if (store.is_new_target(target))
            return true;
    }

    return false;
}

}
