// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <algorithm>
#include <cstddef>
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
#include "object_store.hpp"
#include "scalar_negated_condition.hpp"
#include "transformer/base.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

// Support for key path, only raise an event when there key path is actually present
// When using key paths containing a scalar or a single-value array, report the value that didn't
// match Ignore "unevaluated" non-matches (e,g. string shorter than min_length on match_regex)
namespace {

enum class match_status : uint8_t {
    unknown,  // No data could be evaluated
    no_match, // Data was evaluated but there was no match
    match     // Data was evaluated and there was a match
};

template <typename Iterator>
match_status eval_object(Iterator &it, std::string_view address, const matcher::base &matcher,
    const std::span<const transformer_id> &transformers, const object_limits &limits)
{
    // The iterator is guaranteed to be valid at this point, which means the
    // object pointer should not be nullptr
    ddwaf_object src = *(*it);

    if (src.type == DDWAF_OBJ_STRING) {
        if (src.stringValue == nullptr) {
            return match_status::no_match;
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
                    return match_status::no_match;
                }

                DDWAF_TRACE("Target {} matched parameter value {}", address, highlight);

                return match_status::match;
            }
        }
    }

    auto [res, highlight] = matcher.match(src);
    if (!res) {
        return match_status::no_match;
    }

    DDWAF_TRACE("Target {} matched parameter value {}", address, highlight);

    return match_status::match;
}

template <typename Iterator>
match_status eval_target(Iterator &it, std::string_view address, const matcher::base &matcher,
    const std::span<const transformer_id> &transformers, const object_limits &limits,
    ddwaf::timer &deadline)
{
    auto status = match_status::unknown;
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (!matcher.is_supported_type(it.type())) {
            continue;
        }

        status = eval_object(it, address, matcher, transformers, limits);
        if (status == match_status::match) {
            // If this target matched, we can stop processing
            break;
        }
    }

    return status;
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

// TODO Refactor from exists
const ddwaf_object *find_key(
    const ddwaf_object &parent, std::string_view key, const object_limits &limits)
{
    const std::size_t size =
        std::min(static_cast<uint32_t>(parent.nbEntries), limits.max_container_size);
    for (std::size_t i = 0; i < size; ++i) {
        const auto &child = parent.array[i];

        if (child.parameterName == nullptr) [[unlikely]] {
            continue;
        }
        const std::string_view child_key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};

        if (key == child_key) {
            return &child;
        }
    }

    return nullptr;
}

const ddwaf_object *find_key_path(const ddwaf_object *root, std::span<const std::string> key_path,
    const exclusion::object_set_ref &objects_excluded, const object_limits &limits)
{
    if (key_path.empty()) {
        return root;
    }

    if (root->type == DDWAF_OBJ_MAP) {
        auto it = key_path.begin();
        while ((root = find_key(*root, *it, limits)) != nullptr) {
            if (objects_excluded.contains(root)) {
                break;
            }

            if (++it == key_path.end()) {
                return root;
            }

            if (root->type != DDWAF_OBJ_MAP) {
                break;
            }
        }
    }

    return nullptr;
}

} // namespace

eval_result scalar_negated_condition::eval(condition_cache &cache, const object_store &store,
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

    if (target_.source == data_source::keys) {
        object::key_iterator it(object, target_.key_path, objects_excluded, limits);
        auto status =
            eval_target(it, target_.name, *matcher, target_.transformers, limits, deadline);

        if (status == match_status::no_match) {
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
        const auto *target_object =
            find_key_path(object, target_.key_path, objects_excluded, limits);
        if (target_object == nullptr) {
            return {.outcome = false, .ephemeral = false};
        }

        object::value_iterator it(object, {}, objects_excluded, limits);
        auto status =
            eval_target(it, target_.name, *matcher, target_.transformers, limits, deadline);

        if (status == match_status::no_match) {
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
