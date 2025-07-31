// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>

#include "clock.hpp"
#include "condition/base.hpp"
#include "ddwaf.h"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "negated_scalar_condition.hpp"
#include "object_helpers.hpp"
#include "object_store.hpp"
#include "transformer/base.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

enum class match_result : uint8_t {
    unknown,  // No data could be evaluated
    no_match, // Data was evaluated but there was no match
    match     // Data was evaluated and there was a match
};

template <typename Iterator>
match_result eval_object(Iterator &it, std::string_view address, const matcher::base &matcher,
    const std::span<const transformer_id> &transformers, const object_limits &limits)
{
    // The iterator is guaranteed to be valid at this point, which means the
    // object pointer should not be nullptr
    ddwaf_object src = *(*it);

    if (src.type == DDWAF_OBJ_STRING) {
        if (src.stringValue == nullptr) {
            return match_result::no_match;
        }

        src.nbEntries = find_string_cutoff(src.stringValue, src.nbEntries, limits);
        if (!transformers.empty()) {
            ddwaf_object dst;
            ddwaf_object_invalid(&dst);

            auto transformed = transformer::manager::transform(src, dst, transformers);
            const scope_exit on_exit([&dst] { ddwaf_object_free(&dst); });
            if (transformed) {
                auto [res, highlight] = matcher.match(dst);
                if (!res) {
                    return match_result::no_match;
                }

                DDWAF_TRACE("Target {} matched parameter value {}", address, highlight);

                return match_result::match;
            }
        }
    }

    auto [res, highlight] = matcher.match(src);
    if (!res) {
        return match_result::no_match;
    }

    DDWAF_TRACE("Target {} matched parameter value {}", address, highlight);

    return match_result::match;
}

template <typename Iterator>
match_result eval_target(Iterator &it, std::string_view address, const matcher::base &matcher,
    const std::span<const transformer_id> &transformers, const object_limits &limits,
    ddwaf::timer &deadline)
{
    // We start with the assumption that the object can't be evaluated,
    // but the moment a single value within the object is compatible
    // we either report match or no_match.
    auto result = match_result::unknown;
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (!matcher.is_supported_type(it.type())) {
            continue;
        }

        result = eval_object(it, address, matcher, transformers, limits);
        if (result == match_result::match) {
            // If this target matched, we can stop processing
            break;
        }
    }

    return result;
}

const matcher::base *get_matcher(const std::unique_ptr<matcher::base> &matcher,
    const std::string &data_id, const matcher_mapper &dynamic_matchers)
{
    if (matcher || data_id.empty()) {
        return matcher.get();
    }

    auto it = dynamic_matchers.find(data_id);
    if (it != dynamic_matchers.end()) {
        return it->second.get();
    }

    return nullptr;
}

} // namespace

eval_result negated_scalar_condition::eval(condition_cache &cache, const object_store &store,
    const exclusion::object_set_ref &objects_excluded, const matcher_mapper &dynamic_matchers,
    const object_limits &limits, ddwaf::timer &deadline) const
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    const auto *matcher = get_matcher(matcher_, data_id_, dynamic_matchers);
    if (matcher == nullptr) {
        return {};
    }

    if (cache.targets.size() != 1) {
        cache.targets.assign(1, nullptr);
    }

    auto [object, attr] = store.get_target(target_.index);
    if (object == nullptr || object == cache.targets[0]) {
        return {};
    }

    const bool ephemeral = (attr == object_store::attribute::ephemeral);
    if (!ephemeral) {
        cache.targets[0] = object;
    }

    const auto *target_object =
        object::find_key_path(object, target_.key_path, objects_excluded, limits);
    if (target_object == nullptr) {
        return {.outcome = false, .ephemeral = false};
    }

    // The goal is to determine if the object can be evaluated and if there's a match
    //   - If the object can't be evaluated due to containing incompatible types, we don't
    //     consider this a negated match, so we return false
    //   - If the object can be evaluated and it results in a match, we return false
    //   - If the object can be evaluated and it doesn't result in a match, we return true
    if (target_.source == data_source::keys) {
        // If the object within the key path is not a map, we consider this an
        // object which can't be evaluated
        if (target_object->type != DDWAF_OBJ_MAP) {
            return {.outcome = false, .ephemeral = false};
        }

        object::key_iterator it(target_object, {}, objects_excluded, limits);
        auto result =
            eval_target(it, target_.name, *matcher, target_.transformers, limits, deadline);

        if (result == match_result::no_match) {
            cache.match = {{.args = {{.name = "input"sv,
                                .resolved = {},
                                .address = target_.name,
                                .key_path = {target_.key_path.begin(), target_.key_path.end()}}},
                .highlights = {},
                .operator_name = matcher->negated_name(),
                .operator_value = matcher->to_string(),
                .ephemeral = ephemeral}};
            return {.outcome = true, .ephemeral = ephemeral};
        }
    } else {
        object::value_iterator it(target_object, {}, objects_excluded, limits);
        auto result =
            eval_target(it, target_.name, *matcher, target_.transformers, limits, deadline);

        // If the result is unknown, we assume the contents of the object couldn't be
        // evaluated
        if (result == match_result::no_match) {
            // For display purpose, treat single-value arrays as scalars
            if (target_object->type == DDWAF_OBJ_ARRAY && target_object->nbEntries == 1) {
                target_object = &target_object->array[0];
            }

            cache.match = {{.args = {{.name = "input"sv,
                                .resolved = object_to_string(*target_object),
                                .address = target_.name,
                                .key_path = {target_.key_path.begin(), target_.key_path.end()}}},
                .highlights = {},
                .operator_name = matcher->negated_name(),
                .operator_value = matcher->to_string(),
                .ephemeral = ephemeral}};
            return {.outcome = true, .ephemeral = ephemeral};
        }
    }

    return {.outcome = false, .ephemeral = false};
}

} // namespace ddwaf
