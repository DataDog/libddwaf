// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <condition.hpp>

#include <waf.hpp>

#include "clock.hpp"
#include <exception.hpp>
#include <log.hpp>
#include <memory>

namespace ddwaf {

std::optional<event::match> condition::match_object(const ddwaf_object *object) const
{
    decltype(processor_) processor;
    if (mutable_) {
        processor = std::atomic_load(&processor_);
    } else {
        processor = processor_;
    }

    const bool has_transform = !transformers_.empty();
    bool transform_required = false;

    if (has_transform) {
        // This codepath is shared with the mutable path. The structure can't be const :/
        transform_required =
            PWTransformer::doesNeedTransform(transformers_, const_cast<ddwaf_object *>(object));
    }

    size_t length =
        find_string_cutoff(object->stringValue, object->nbEntries, limits_.max_string_length);

    // If we don't have transform to perform, or if they're irrelevant, no need to waste time
    // copying and allocating data
    if (!has_transform || !transform_required) {
        return processor->match({object->stringValue, length});
    }

    ddwaf_object copy;
    ddwaf_object_stringl(&copy, (const char *)object->stringValue, length);

    std::unique_ptr<ddwaf_object, decltype(&ddwaf_object_free)> scope(&copy, ddwaf_object_free);

    // Transform it and pick the pointer to process
    bool transformFailed = false;
    for (const PW_TRANSFORM_ID &transform : transformers_) {
        transformFailed = !PWTransformer::transform(transform, &copy);
        if (transformFailed || (copy.type == DDWAF_OBJ_STRING && copy.nbEntries == 0)) {
            break;
        }
    }

    if (transformFailed) {
        return processor->match({object->stringValue, length});
    }

    return processor->match_object(&copy);
}

template <typename T>
std::optional<event::match> condition::match_target(T &it, ddwaf::timer &deadline) const
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != DDWAF_OBJ_STRING) {
            continue;
        }

        auto optional_match = match_object(*it);
        if (!optional_match.has_value()) {
            continue;
        }

        optional_match->key_path = std::move(it.get_current_path());
        // If this target matched, we can stop processing
        return optional_match;
    }

    return std::nullopt;
}

std::optional<event::match> condition::match(const object_store &store,
    const ddwaf::manifest &manifest, bool run_on_new, ddwaf::timer &deadline) const
{
    for (const auto &target : targets_) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        // TODO: the conditions should keep track of the targets already
        // checked (?).
        if (run_on_new && !store.is_new_target(target)) {
            continue;
        }

        const auto &info = manifest.get_target_info(target);

        // TODO: iterators could be cached to avoid reinitialisation

        auto object = store.get_target(target);
        if (object == nullptr) {
            continue;
        }

        std::optional<event::match> optional_match;
        if (source_ == data_source::keys) {
            object::key_iterator it(object, info.key_path, limits_);
            optional_match = match_target(it, deadline);
        } else {
            object::value_iterator it(object, info.key_path, limits_);
            optional_match = match_target(it, deadline);
        }

        if (optional_match.has_value()) {
            optional_match->source = info.name;

            DDWAF_TRACE("Target %s matched parameter value %s", info.name.c_str(),
                optional_match->resolved.c_str());
            return optional_match;
        }
    }

    return std::nullopt;
}

} // namespace ddwaf
