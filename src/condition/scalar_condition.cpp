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
#include "cow_string.hpp"
#include "dynamic_string.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "matcher/prefilter_cache.hpp"
#include "matcher/regex_prefilter.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "scalar_condition.hpp"
#include "transformer/base.hpp"
#include "transformer/manager.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

// The prefilter of the matcher, with the cache of literal scans of the current
// evaluation, if both are available
struct prefilter_ref {
    const matcher::regex_prefilter *prefilter{nullptr};
    matcher::prefilter_cache *cache{nullptr};
};

template <typename Iterator>
std::optional<condition_match> eval_object(Iterator &it, std::string_view address,
    const matcher::base &matcher, const std::span<const transformer_id> &transformers,
    prefilter_ref prefilter)
{
    // The iterator is guaranteed to be valid at this point, which means the
    // object pointer should not be nullptr
    const object_view src = *it;
    if (src.is_string()) {
        std::optional<cow_string> transformed;
        bool transformed_valid = false;
        if (prefilter.cache != nullptr && prefilter.prefilter != nullptr &&
            !prefilter.cache->may_match(
                *prefilter.prefilter, src, transformers, transformed, transformed_valid)) {
            return {};
        }

        if (!transformers.empty()) {
            if (!transformed_valid) {
                transformed = transformer::manager::transform(src, transformers);
            }
            if (transformed) {
                auto transformed_sv = static_cast<std::string_view>(transformed.value());
                auto [res, highlight] = matcher.match(transformed_sv);
                if (!res) {
                    return {};
                }

                DDWAF_TRACE("Target {} matched parameter value {}", address, highlight);

                return {{{{"input"sv, static_cast<dynamic_string>(transformed.value()), address,
                             it.get_current_path()}},
                    {std::move(highlight)}, matcher.name(), matcher.to_string()}};
            }
        }
    }

    auto [res, highlight] = matcher.match(src);
    if (!res) {
        return {};
    }

    DDWAF_TRACE("Target {} matched parameter value {}", address, highlight);

    // TODO fix conversion to dynamic_string
    return {{{{"input"sv, src.convert<std::string>(), address, it.get_current_path()}},
        {std::move(highlight)}, matcher.name(), matcher.to_string()}};
}

template <typename Iterator>
std::optional<condition_match> eval_target(Iterator &it, std::string_view address,
    const matcher::base &matcher, const std::span<const transformer_id> &transformers,
    prefilter_ref prefilter, ddwaf::timer &deadline)
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (!matcher.is_supported_type(it.type())) {
            continue;
        }

        auto match = eval_object(it, address, matcher, transformers, prefilter);
        if (match) {
            // If this target matched, we can stop processing
            return match;
        }
    }

    return {};
}

prefilter_ref resolve_prefilter(const matcher::base &matcher)
{
    prefilter_ref prefilter{.prefilter = matcher.get_prefilter()};
    if (prefilter.prefilter != nullptr) {
        prefilter.cache = matcher::prefilter_cache::current();
        if (prefilter.cache != nullptr && !prefilter.cache->supports(*prefilter.prefilter)) {
            prefilter.cache = nullptr;
        }
    }
    return prefilter;
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

bool scalar_condition::eval(condition_cache &cache, const object_store &store,
    const object_set_ref &objects_excluded, const matcher_mapper &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    const auto *matcher = get_matcher(matcher_, data_id_, dynamic_matchers);
    if (matcher == nullptr) {
        return {};
    }

    if (cache.targets.size() != targets_.size()) {
        cache.targets.assign(targets_.size(), {});
    }

    // Only resolved once there is something to evaluate
    std::optional<prefilter_ref> prefilter;

    for (unsigned i = 0; i < targets_.size(); ++i) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const auto &target = targets_[i];
        auto object = store.get_target(target.index);
        if (!object.has_value() || object == cache.targets[i]) {
            continue;
        }

        cache.targets[i] = object;

        if (!prefilter.has_value()) {
            prefilter = resolve_prefilter(*matcher);
        }

        std::optional<condition_match> match;
        // TODO: iterators could be cached to avoid reinitialisation
        if (target.source == data_source::keys) {
            key_iterator it(object, target.key_path, objects_excluded);
            match =
                eval_target(it, target.name, *matcher, target.transformers, *prefilter, deadline);
        } else {
            value_iterator it(object, target.key_path, objects_excluded);
            match =
                eval_target(it, target.name, *matcher, target.transformers, *prefilter, deadline);
        }

        if (match.has_value()) {
            cache.match = std::move(match);
            return true;
        }
    }

    return false;
}

} // namespace ddwaf
