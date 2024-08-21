// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "scalar_condition.hpp"
#include "clock.hpp"
#include "condition/base.hpp"
#include "ddwaf.h"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "transformer/base.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

using namespace std::literals;

namespace ddwaf {

namespace {

template <typename Iterator>
std::optional<condition_match> eval_object(Iterator &it, std::string_view address, bool ephemeral,
    const matcher::base &matcher, const std::span<const transformer_id> &transformers,
    const object_limits &limits)
{
    // The iterator is guaranteed to be valid at this point, which means the
    // object pointer should not be nullptr
    ddwaf_object src = *(*it);

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

                return {{{{"input"sv, object_to_string(dst), address, it.get_current_path()}},
                    {std::move(highlight)}, matcher.name(), matcher.to_string(), ephemeral}};
            }
        }
    }

    auto [res, highlight] = matcher.match(src);
    if (!res) {
        return {};
    }

    DDWAF_TRACE("Target {} matched parameter value {}", address, highlight);

    return {{{{"input"sv, object_to_string(src), address, it.get_current_path()}},
        {std::move(highlight)}, matcher.name(), matcher.to_string(), ephemeral}};
}

template <typename Iterator>
std::optional<condition_match> eval_target(Iterator &it, std::string_view address, bool ephemeral,
    const matcher::base &matcher, const std::span<const transformer_id> &transformers,
    const object_limits &limits, ddwaf::timer &deadline)
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != matcher.supported_type()) {
            continue;
        }

        auto match = eval_object(it, address, ephemeral, matcher, transformers, limits);
        if (match.has_value()) {
            // If this target matched, we can stop processing
            return match;
        }
    }

    return {};
}

} // namespace

const matcher::base *scalar_condition::get_matcher(
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers) const
{
    if (matcher_ || data_id_.empty()) {
        return matcher_.get();
    }

    auto it = dynamic_matchers.find(data_id_);
    if (it != dynamic_matchers.end()) {
        return it->second.get();
    }

    return nullptr;
}

eval_result scalar_condition::eval(condition_cache &cache, const object_store &store,
    const exclusion::object_set_ref &objects_excluded,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    const auto *matcher = get_matcher(dynamic_matchers);
    if (matcher == nullptr) {
        return {};
    }

    if (cache.targets.size() != targets_.size()) {
        cache.targets.assign(targets_.size(), nullptr);
    }

    for (unsigned i = 0; i < targets_.size(); ++i) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const auto &target = targets_[i];
        auto [object, attr] = store.get_target(target.index);
        if (object == nullptr || object == cache.targets[i]) {
            continue;
        }

        const bool ephemeral = (attr == object_store::attribute::ephemeral);
        if (!ephemeral) {
            cache.targets[i] = object;
        }

        std::optional<condition_match> match;
        // TODO: iterators could be cached to avoid reinitialisation
        if (target.source == data_source::keys) {
            object::key_iterator it(object, target.key_path, objects_excluded, limits_);
            match = eval_target(
                it, target.name, ephemeral, *matcher, target.transformers, limits_, deadline);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits_);
            match = eval_target(
                it, target.name, ephemeral, *matcher, target.transformers, limits_, deadline);
        }

        if (match.has_value()) {
            cache.match = std::move(match);
            return {true, ephemeral};
        }
    }

    return {false, false};
}

} // namespace ddwaf
