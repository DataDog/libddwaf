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
#include "dynamic_string.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object.hpp"
#include "object_store.hpp"
#include "scalar_condition.hpp"
#include "transformer/base.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ddwaf {

namespace {

template <typename Iterator>
std::optional<condition_match> eval_object(Iterator &it, std::string_view address,
    evaluation_scope scope, const matcher::base &matcher,
    const std::span<const transformer_id> &transformers)
{
    // The iterator is guaranteed to be valid at this point, which means the
    // object pointer should not be nullptr
    const object_view src = *it;
    if (src.is_string()) {
        if (!transformers.empty()) {
            auto transformed = transformer::manager::transform(src, transformers);
            if (transformed) {
                auto transformed_sv = static_cast<std::string_view>(transformed.value());
                auto [res, highlight] = matcher.match(transformed_sv);
                if (!res) {
                    return {};
                }

                DDWAF_TRACE("Target {} matched parameter value {}", address, highlight);

                return {{{{"input"sv, dynamic_string::from_movable_string(transformed.value()),
                             address, it.get_current_path()}},
                    {std::move(highlight)}, matcher.name(), matcher.to_string(), scope}};
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
        {std::move(highlight)}, matcher.name(), matcher.to_string(), scope}};
}

template <typename Iterator>
std::optional<condition_match> eval_target(Iterator &it, std::string_view address,
    evaluation_scope scope, const matcher::base &matcher,
    const std::span<const transformer_id> &transformers, ddwaf::timer &deadline)
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (!matcher.is_supported_type(it.type())) {
            continue;
        }

        auto match = eval_object(it, address, scope, matcher, transformers);
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
    ddwaf::timer &deadline) const
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

        const auto &target = targets_[i];
        auto [object, scope] = store.get_target(target.index);
        if (!object.has_value() ||
            (object == cache.targets[i].first && scope == cache.targets[i].second)) {
            continue;
        }

        cache.targets[i] = {object, scope};

        std::optional<condition_match> match;
        // TODO: iterators could be cached to avoid reinitialisation
        if (target.source == data_source::keys) {
            key_iterator it(object, target.key_path, objects_excluded);
            match = eval_target(it, target.name, scope, *matcher, target.transformers, deadline);
        } else {
            value_iterator it(object, target.key_path, objects_excluded);
            match = eval_target(it, target.name, scope, *matcher, target.transformers, deadline);
        }

        if (match.has_value()) {
            cache.match = std::move(match);
            return {.outcome = true, .scope = scope};
        }
    }

    return {.outcome = false, .scope = {}};
}

} // namespace ddwaf
