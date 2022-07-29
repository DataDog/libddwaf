// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <rule.hpp>

#include <waf.hpp>

#include "clock.hpp"
#include <log.hpp>

namespace ddwaf
{

bool condition::match_object(const ddwaf_object* baseInput,
  MatchGatherer& gatherer) const
{
    const bool hasTransformation        = !transformation.empty();
    bool transformationWillChangeString = false;

    if (hasTransformation)
    {
        // This codepath is shared with the mutable path. The structure can't be const :/
        transformationWillChangeString = PWTransformer::doesNeedTransform(transformation,
            const_cast<ddwaf_object *>(baseInput));
    }

    size_t length = find_string_cutoff(baseInput->stringValue,
            baseInput->nbEntries, limits_.max_string_length);

    //If we don't have transformation to perform, or if they're irrelevant, no need to waste time copying and allocating data
    if (!hasTransformation || !transformationWillChangeString) {
        return processor->match(baseInput->stringValue, length, gatherer);
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
        matched |= processor->match(baseInput->stringValue, length, gatherer);
    } else {
        matched |= processor->match_object(&copyInput, gatherer);
    }

    // Otherwise, the caller is in charge of freeing the pointer
    ddwaf_object_free(&copyInput);

    return matched;
}

template <typename T>
condition::status condition::match_target(T &it,
    const std::string &name,
    ddwaf::timer& deadline,
    PWRetManager& retManager) const
{
    for (; it; ++it) {
        if (deadline.expired()) {
            return status::timeout;
        }

        MatchGatherer gather;
        if (it.type() != DDWAF_OBJ_STRING) { continue; }
        if (!match_object(*it, gather)) { continue; }

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

condition::status condition::match(const object_store& store,
    const ddwaf::manifest &manifest, bool run_on_new,
    ddwaf::timer& deadline, PWRetManager& retManager) const
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

        if (res == status::matched || res == status::timeout) {
            return res;
        }
    }

    return status::no_match;
}

rule::rule(index_type index_, std::string &&id_, std::string &&name_,
  std::string &&category_, std::vector<condition> &&conditions_,
  std::vector<std::string> &&actions_):
  index(index_), id(std::move(id_)), name(std::move(name_)),
  category(std::move(category_)), conditions(std::move(conditions_)),
  actions(std::move(actions_))
{
    for (auto &cond : conditions) {
        targets.insert(cond.targets.begin(), cond.targets.end());
    }
}

bool rule::has_new_targets(const object_store &store) const
{
    for (const auto& target : targets)
    {
        if (store.is_new_target(target)) {
            return true;
        }
    }

    return false;
}

}
