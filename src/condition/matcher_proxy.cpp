// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "matcher_proxy.hpp"
#include "exception.hpp"
#include "iterator.hpp"
#include "transformer/manager.hpp"

namespace ddwaf::condition {

namespace {

// TODO store as std::variant<memory::string, bool, int64_t, uint64_t>?
std::string object_to_string(const ddwaf_object &object)
{
    if (object.type == DDWAF_OBJ_STRING) {
        return std::string{object.stringValue, static_cast<std::size_t>(object.nbEntries)};
    }

    if (object.type == DDWAF_OBJ_BOOL) {
        return to_string<std::string>(object.boolean);
    }

    if (object.type == DDWAF_OBJ_SIGNED) {
        return to_string<std::string>(object.intValue);
    }

    if (object.type == DDWAF_OBJ_UNSIGNED) {
        return to_string<std::string>(object.uintValue);
    }

    if (object.type == DDWAF_OBJ_FLOAT) {
        return to_string<std::string>(object.f64);
    }

    return {};
}

std::optional<event::match> eval_object(const ddwaf_object *object, const matcher::base &matcher,
    const std::span<const transformer_id> &transformers, const object_limits &limits)
{
    ddwaf_object src = *object;

    if (src.type == DDWAF_OBJ_STRING) {
        if (src.stringValue == nullptr) {
            return std::nullopt;
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
                    return std::nullopt;
                }
                return {{object_to_string(dst), std::move(highlight), matcher.name(),
                    matcher.to_string(), {}, {}}};
            }
        }
    }

    auto [res, highlight] = matcher.match(src);
    if (!res) {
        return std::nullopt;
    }

    return {
        {object_to_string(src), std::move(highlight), matcher.name(), matcher.to_string(), {}, {}}};
}

template <typename Iterator>
std::optional<event::match> eval_target(Iterator &it, const matcher::base &matcher,
    const std::span<const transformer_id> &transformers, const object_limits &limits,
    ddwaf::timer &deadline)
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != matcher.supported_type()) {
            continue;
        }

        auto optional_match = eval_object(*it, matcher, transformers, limits);
        if (!optional_match.has_value()) {
            continue;
        }

        optional_match->key_path = std::move(it.get_current_path());
        // If this target matched, we can stop processing
        return optional_match;
    }

    return std::nullopt;
}

} // namespace

const matcher::base *matcher_proxy::get_matcher(
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

eval_result matcher_proxy::eval(cache_type &cache, const object_store &store,
    const exclusion::object_set_ref &objects_excluded,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    const object_limits &limits, ddwaf::timer &deadline) const
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
        auto [object, attr] = store.get_target(target.root);
        if (object == nullptr || object == cache.targets[i]) {
            continue;
        }

        const bool ephemeral = (attr == object_store::attribute::ephemeral);
        if (!ephemeral) {
            cache.targets[i] = object;
        }

        std::optional<event::match> optional_match;
        // TODO: iterators could be cached to avoid reinitialisation
        if (target.source == data_source::keys) {
            object::key_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(it, *matcher, target.transformers, limits, deadline);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(it, *matcher, target.transformers, limits, deadline);
        }

        if (optional_match.has_value()) {
            optional_match->address = target.name;
            optional_match->ephemeral = ephemeral;
            DDWAF_TRACE(
                "Target {} matched parameter value {}", target.name, optional_match->resolved);

            cache.match = std::move(optional_match);
            return {true, ephemeral};
        }
    }

    return {false, false};
}

} // namespace ddwaf::condition
