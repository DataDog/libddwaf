// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <condition.hpp>

#include <exception.hpp>
#include <log.hpp>
#include <memory>

#include "transformer_cache.hpp"

namespace ddwaf {

std::optional<event::match> condition::match_object(const ddwaf_object *object,
    const rule_processor::base::ptr &processor, const std::vector<PW_TRANSFORM_ID> &transformers,
    transformer_cache &tcache) const
{
    const size_t length =
        find_string_cutoff(object->stringValue, object->nbEntries, limits_.max_string_length);

    const auto [copy, cached] = tcache.transform(object, length, transformers);
    if (copy == nullptr) {
        return processor->match({object->stringValue, length});
    }

    return processor->match_object(copy);
}

template <typename T>
std::optional<event::match> condition::match_target(T &it,
    const rule_processor::base::ptr &processor, const std::vector<PW_TRANSFORM_ID> &transformers,
    transformer_cache &tcache, ddwaf::timer &deadline) const
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != DDWAF_OBJ_STRING) {
            continue;
        }

        auto optional_match = match_object(*it, processor, transformers, tcache);
        if (!optional_match.has_value()) {
            continue;
        }

        optional_match->key_path = std::move(it.get_current_path());
        // If this target matched, we can stop processing
        return optional_match;
    }

    return std::nullopt;
}

const rule_processor::base::ptr &condition::get_processor(
    const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors) const
{
    if (processor_ || data_id_.empty()) {
        return processor_;
    }

    auto it = dynamic_processors.find(data_id_);
    if (it == dynamic_processors.end()) {
        return processor_;
    }

    return it->second;
}

std::optional<event::match> condition::match(const object_store &store,
    const std::unordered_set<const ddwaf_object *> &objects_excluded, bool run_on_new,
    const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
    transformer_cache &tcache, ddwaf::timer &deadline) const
{
    const auto &processor = get_processor(dynamic_processors);
    if (!processor) {
        DDWAF_DEBUG("Condition doesn't have a valid processor");
        return std::nullopt;
    }

    for (const auto &[target, name, key_path, transformers, source] : targets_) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        // TODO: the conditions should keep track of the targets already
        // checked (?).
        if (run_on_new && !store.is_new_target(target)) {
            continue;
        }

        // TODO: iterators could be cached to avoid reinitialisation
        const auto *object = store.get_target(target);
        if (object == nullptr) {
            continue;
        }

        std::optional<event::match> optional_match;
        if (source == data_source::keys) {
            object::key_iterator it(object, key_path, objects_excluded, limits_);
            optional_match = match_target(it, processor, transformers, tcache, deadline);
        } else {
            object::value_iterator it(object, key_path, objects_excluded, limits_);
            optional_match = match_target(it, processor, transformers, tcache, deadline);
        }

        if (optional_match.has_value()) {
            optional_match->address = name;

            DDWAF_TRACE("Target %s matched parameter value %s", name.c_str(),
                optional_match->resolved.c_str());
            return optional_match;
        }
    }

    return std::nullopt;
}

} // namespace ddwaf
