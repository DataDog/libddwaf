// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

#include "clock.hpp"
#include "condition/base.hpp"
#include "ddwaf.h"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_converter.hpp" // IWYU pragma: keep
#include "object_store.hpp"
#include "object_view.hpp"
#include "scalar_condition.hpp"
#include "transformer/base.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

template <typename ResultType, typename Iterator>
ResultType eval_object(Iterator &it, std::string_view address, bool ephemeral,
    const matcher::base &matcher, const std::span<const transformer_id> &transformers,
    const object_limits &limits)
    requires(std::is_same_v<ResultType, bool> ||
             std::is_same_v<ResultType, std::optional<condition_match>>)
{
    // The iterator is guaranteed to be valid at this point, which means the
    // object pointer should not be nullptr
    ddwaf_object src = *((*it).ptr());

    if (src.type == DDWAF_OBJ_STRING) {
        if (src.stringValue == nullptr) {
            return {};
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
                    return {};
                }

                DDWAF_TRACE("Target {} matched parameter value {}", address, highlight);

                if constexpr (std::is_same_v<ResultType, bool>) {
                    return true;
                } else {
                    return {{{{"input"sv, object_to_string(dst), address, it.get_current_path()}},
                        {std::move(highlight)}, matcher.name(), matcher.to_string(), ephemeral}};
                }
            }
        }
    }

    auto [res, highlight] = matcher.match(src);
    if (!res) {
        return {};
    }

    DDWAF_TRACE("Target {} matched parameter value {}", address, highlight);

    if constexpr (std::is_same_v<ResultType, bool>) {
        return true;
    } else {
        return {{{{"input"sv, object_to_string(src), address, it.get_current_path()}},
            {std::move(highlight)}, matcher.name(), matcher.to_string(), ephemeral}};
    }
}

template <typename ResultType, typename Iterator>
ResultType eval_target(Iterator &it, std::string_view address, bool ephemeral,
    const matcher::base &matcher, const std::span<const transformer_id> &transformers,
    const object_limits &limits, ddwaf::timer &deadline)
    requires(std::is_same_v<ResultType, bool> ||
             std::is_same_v<ResultType, std::optional<condition_match>>)
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (!matcher.is_supported_type(it.type())) {
            continue;
        }

        auto match = eval_object<ResultType>(it, address, ephemeral, matcher, transformers, limits);
        if (match) {
            // If this target matched, we can stop processing
            return match;
        }
    }

    return {};
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

eval_result scalar_condition::eval(condition_cache &cache, const object_store &store,
    const exclusion::object_set_ref &objects_excluded, const matcher_mapper &dynamic_matchers,
    const object_limits &limits, ddwaf::timer &deadline) const
{
    const auto *matcher = get_matcher(matcher_, data_id_, dynamic_matchers);
    if (matcher == nullptr) {
        return {};
    }

    if (cache.targets.size() != targets_.size()) {
        cache.targets.assign(targets_.size(), {});
    }

    for (unsigned i = 0; i < targets_.size(); ++i) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        // TODO Fix this once store returns view
        const auto &target = targets_[i];
        auto [legacy_object, attr] = store.get_target(target.index);
        object_view const object = legacy_object;
        if (!object.has_value() || object == cache.targets[i]) {
            continue;
        }

        const bool ephemeral = (attr == object_store::attribute::ephemeral);
        if (!ephemeral) {
            cache.targets[i] = object;
        }

        std::optional<condition_match> match;
        // TODO: iterators could be cached to avoid reinitialisation
        if (target.source == data_source::keys) {
            key_iterator it(object, target.key_path, objects_excluded, limits);
            match = eval_target<std::optional<condition_match>>(
                it, target.name, ephemeral, *matcher, target.transformers, limits, deadline);
        } else {
            value_iterator it(object, target.key_path, objects_excluded, limits);
            match = eval_target<std::optional<condition_match>>(
                it, target.name, ephemeral, *matcher, target.transformers, limits, deadline);
        }

        if (match.has_value()) {
            cache.match = std::move(match);
            return {.outcome = true, .ephemeral = ephemeral};
        }
    }

    return {.outcome = false, .ephemeral = false};
}

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
        cache.targets.assign(1, {});
    }

    auto [legacy_object, attr] = store.get_target(target_.index);
    object_view const object = legacy_object;
    if (!object.has_value() || object == cache.targets[0]) {
        return {};
    }

    const bool ephemeral = (attr == object_store::attribute::ephemeral);
    if (!ephemeral) {
        cache.targets[0] = object;
    }

    bool match = false;
    if (target_.source == data_source::keys) {
        key_iterator it(object, target_.key_path, objects_excluded, limits);
        match = eval_target<bool>(
            it, target_.name, ephemeral, *matcher, target_.transformers, limits, deadline);
    } else {
        value_iterator it(object, target_.key_path, objects_excluded, limits);
        match = eval_target<bool>(
            it, target_.name, ephemeral, *matcher, target_.transformers, limits, deadline);
    }

    if (!match) {
        cache.match = {{.args = {{.name = "input"sv,
                            .resolved = object.convert<std::string>(), // object_to_string(*object),
                            .address = target_.name,
                            .key_path = {target_.key_path.begin(), target_.key_path.end()}}},
            .highlights = {},
            .operator_name = matcher->negated_name(),
            .operator_value = matcher->to_string(),
            .ephemeral = ephemeral}};
        return {.outcome = true, .ephemeral = ephemeral};
    }

    return {.outcome = false, .ephemeral = false};
}

} // namespace ddwaf
