// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <charconv>
#include <memory>

#include "exception.hpp"
#include "expression.hpp"
#include "log.hpp"
#include "transformer/manager.hpp"

namespace ddwaf {

std::optional<event::match> expression::evaluator::eval_object(const ddwaf_object *object,
    const operation::base::ptr &processor, const std::vector<transformer_id> &transformers) const
{
    const size_t length =
        find_string_cutoff(object->stringValue, object->nbEntries, limits.max_string_length);

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
std::optional<event::match> expression::evaluator::eval_target(
    T &it, const operation::base::ptr &processor, const std::vector<transformer_id> &transformers)
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != DDWAF_OBJ_STRING) {
            continue;
        }

        auto optional_match = eval_object(*it, processor, transformers);
        if (optional_match.has_value()) {
            optional_match->key_path = std::move(it.get_current_path());
            // If this target matched, we can stop processing
            return optional_match;
        }
    }

    return std::nullopt;
}

const operation::base::ptr &expression::evaluator::get_processor(const condition &cond) const
{
    if (cond.processor || cond.data_id.empty()) {
        return cond.processor;
    }

    auto it = dynamic_processors.find(cond.data_id);
    if (it == dynamic_processors.end()) {
        return cond.processor;
    }

    return it->second;
}

// NOLINTNEXTLINE(misc-no-recursion)
std::optional<event::match> expression::evaluator::eval_condition(
    const condition &cond, condition::cache_type &cond_cache)
{
    const auto &processor = get_processor(cond);
    if (!processor) {
        DDWAF_DEBUG("Condition doesn't have a valid processor");
        return std::nullopt;
    }

    for (std::size_t ti = 0; ti < cond.targets.size(); ++ti) {
        const auto &target = cond.targets[ti];

        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (cond_cache.targets.find(ti) != cond_cache.targets.end() &&
            !store.is_new_target(target.root)) {
            continue;
        }

        const ddwaf_object *object = store.get_target(target.root);
        if (object == nullptr) {
            continue;
        }

        std::optional<event::match> optional_match;
        // TODO: iterators could be cached to avoid reinitialisation
        if (target.source == data_source::keys) {
            object::key_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(it, processor, target.transformers);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(it, processor, target.transformers);
        }

        cond_cache.targets.emplace(ti);

        if (!optional_match.has_value()) {
            continue;
        }

        DDWAF_TRACE("Target %s matched parameter value %s", target.name.c_str(),
            optional_match->resolved.c_str());

        optional_match->address = target.name;
        cond_cache.result = true;

        return optional_match;
    }

    return std::nullopt;
}

bool expression::evaluator::eval()
{
    if (cache.conditions.capacity() != conditions.size()) {
        cache.conditions.reserve(conditions.size());
    }

    // NOLINTNEXTLINE(readability-use-anyofallof)
    for (std::size_t i = 0; i < conditions.size(); i++) {
        if (cache.conditions.size() == i) {
            cache.conditions.emplace_back(condition::cache_type{});
        }

        auto &cond_cache = cache.conditions[i];
        if (cond_cache.result) {
            continue;
        }

        auto optional_match = eval_condition(*conditions[i], cond_cache);
        if (!optional_match) {
            return false;
        }

        cache.matches.emplace_back(std::move(*optional_match));
    }

    return true;
}

bool expression::eval(cache_type &cache, const object_store &store,
    const std::unordered_set<const ddwaf_object *> &objects_excluded,
    const std::unordered_map<std::string, operation::base::ptr> &dynamic_processors,
    ddwaf::timer &deadline) const
{
    if (!cache.result) {
        evaluator runner{
            deadline, limits_, conditions_, store, objects_excluded, dynamic_processors, cache};
        cache.result = runner.eval();
    }

    return cache.result;
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
    cond->targets.emplace_back(std::move(target));
}

} // namespace ddwaf
