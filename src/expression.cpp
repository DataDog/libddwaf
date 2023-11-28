// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <charconv>
#include <iostream>
#include <memory>

#include "exception.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "log.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

namespace ddwaf {

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

} // namespace

std::optional<event::match> expression::evaluator::eval_object(const ddwaf_object *object,
    const matcher::base &matcher, const std::vector<transformer_id> &transformers) const
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

template <typename T>
std::optional<event::match> expression::evaluator::eval_target(
    T &it, const matcher::base &matcher, const std::vector<transformer_id> &transformers)
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != matcher.supported_type()) {
            continue;
        }

        auto optional_match = eval_object(*it, matcher, transformers);
        if (!optional_match.has_value()) {
            continue;
        }

        optional_match->key_path = std::move(it.get_current_path());
        // If this target matched, we can stop processing
        return optional_match;
    }

    return std::nullopt;
}

const matcher::base *expression::evaluator::get_matcher(const condition &cond) const
{
    if (cond.matcher || cond.data_id.empty()) {
        return cond.matcher.get();
    }

    auto it = dynamic_matchers.find(cond.data_id);
    if (it == dynamic_matchers.end()) {
        return cond.matcher.get();
    }

    return it->second.get();
}

expression::eval_result expression::evaluator::eval_scalar_condition(
    const condition &cond, const matcher::base &matcher, condition::cache_type &cache)
{
    if (cache.targets.size() != cond.targets.size()) {
        cache.targets.assign(cond.targets.size(), nullptr);
    }

    for (unsigned i = 0; i < cond.targets.size(); ++i) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        const auto &target = cond.targets[i];
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
            optional_match = eval_target(it, matcher, target.transformers);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(it, matcher, target.transformers);
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

expression::eval_result expression::evaluator::eval_structured_condition(
    const condition &cond, const matcher::base &matcher, condition::cache_type &cache)
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    bool ephemeral = false;
    std::vector<optional_ref<const ddwaf_object>> args;
    args.reserve(cond.targets.size());
    for (unsigned i = 0; i < cond.targets.size(); ++i) {
        const auto &target = cond.targets[i];
        auto [object, attr] = store.get_target(target.root);
        if (object == nullptr) {
            return {false, false};
        }

        if (attr == object_store::attribute::ephemeral) {
            ephemeral = true;
        }

        args.emplace_back(*object);
    }

    std::optional<event::match> optional_match;
    auto [res, highlight, index] = matcher.match(args);

    if (res) {
        std::string value;

        if (index < args.size()) {
            auto matched_object = args[index];
            if (matched_object.has_value()) {
                value = object_to_string(matched_object->get());
            }
        }

        if (index < cond.targets.size()) {
            const auto &target = cond.targets[index];
            cache.match = event::match{std::move(value), std::move(highlight), matcher.name(),
                matcher.to_string(), target.name, target.key_path, ephemeral};
        } else {
            // This shouldn't ever happen....
            cache.match = event::match{std::move(value), std::move(highlight), matcher.name(),
                matcher.to_string(), "", {}, ephemeral};
        }

        return {true, ephemeral};
    }

    return {false, false};
}

expression::eval_result expression::evaluator::eval_condition(
    const condition &cond, condition::cache_type &cache)
{
    const auto *matcher = get_matcher(cond);
    if (matcher == nullptr) {
        DDWAF_DEBUG("Condition doesn't have a valid matcher");
        return {false, false};
    }

    if (matcher->type() == matcher::matcher_type::scalar) {
        return eval_scalar_condition(cond, *matcher, cache);
    }

    // Structure condition
    return eval_structured_condition(cond, *matcher, cache);
}

expression::eval_result expression::evaluator::eval()
{
    bool ephemeral_match = false;
    for (unsigned i = 0; i < conditions.size(); ++i) {
        const auto &cond = conditions[i];
        auto &cond_cache = cache.conditions[i];

        if (cond_cache.match.has_value() && !cond_cache.match->ephemeral) {
            continue;
        }

        auto [res, ephemeral] = eval_condition(cond, cond_cache);
        if (!res) {
            return {false, false};
        }
        ephemeral_match = ephemeral_match || ephemeral;
    }
    return {true, ephemeral_match};
}

expression::eval_result expression::eval(cache_type &cache, const object_store &store,
    const exclusion::object_set_ref &objects_excluded,
    const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
    ddwaf::timer &deadline) const
{
    if (cache.result || conditions_.empty()) {
        return {true, false};
    }

    if (cache.conditions.size() < conditions_.size()) {
        cache.conditions.assign(conditions_.size(), condition::cache_type{});
    }

    evaluator runner{
        deadline, limits_, conditions_, store, objects_excluded, dynamic_matchers, cache};

    auto res = runner.eval();
    cache.result = res.outcome && !res.ephemeral;
    return res;
}

void expression_builder::add_target(std::string name, std::vector<std::string> key_path,
    std::vector<transformer_id> transformers, expression::data_source source)
{
    expression::condition::target_type target;
    target.root = get_target_index(name);
    target.key_path = std::move(key_path);
    target.name = std::move(name);
    target.transformers = std::move(transformers);
    target.source = source;

    auto &cond = conditions_.back();
    cond.targets.emplace_back(std::move(target));
}

} // namespace ddwaf
