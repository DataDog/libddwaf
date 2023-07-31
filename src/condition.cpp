// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <memory>

#include "condition.hpp"
#include "exception.hpp"
#include "log.hpp"
#include "transformer/manager.hpp"

namespace ddwaf {

std::optional<event::match> condition::match_object(const ddwaf_object *object,
    const operation::base::ptr &processor, const std::vector<transformer_id> &transformers) const
{
    const size_t length =
        find_string_cutoff(object->stringValue, object->nbEntries, limits_.max_string_length);

    if (!transformers.empty()) {
        ddwaf_object src;
        ddwaf_object dst;
        ddwaf_object_stringl_nc(&src, object->stringValue, length);
        ddwaf_object_invalid(&dst);

        auto transformed = transformer::manager::transform(src, dst, transformers);
        scope_exit on_exit([&dst] { ddwaf_object_free(&dst); });
        if (transformed) {
            return processor->match({dst.stringValue, dst.nbEntries});
        }
    }

    return processor->match({object->stringValue, length});
}

template <typename T>
std::optional<event::match> condition::match_target(T &it, const operation::base::ptr &processor,
    const std::vector<transformer_id> &transformers, ddwaf::timer &deadline) const
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != DDWAF_OBJ_STRING) {
            continue;
        }

        auto optional_match = match_object(*it, processor, transformers);
        if (!optional_match.has_value()) {
            continue;
        }

        optional_match->key_path = std::move(it.get_current_path());
        // If this target matched, we can stop processing
        return optional_match;
    }

    return std::nullopt;
}

const operation::base::ptr &condition::get_processor(
    const std::unordered_map<std::string, operation::base::ptr> &dynamic_processors) const
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
    const std::unordered_map<std::string, operation::base::ptr> &dynamic_processors,
    ddwaf::timer &deadline) const
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
        if (source == expression::data_source::keys) {
            object::key_iterator it(object, key_path, objects_excluded, limits_);
            optional_match = match_target(it, processor, transformers, deadline);
        } else {
            object::value_iterator it(object, key_path, objects_excluded, limits_);
            optional_match = match_target(it, processor, transformers, deadline);
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
