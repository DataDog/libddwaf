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
            return processor->match_object(&dst);
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

        DDWAF_TRACE("Value %s", (*it)->stringValue);
        auto optional_match = eval_object(*it, processor, transformers);
        if (!optional_match.has_value()) {
            continue;
        }

        optional_match->key_path = std::move(it.get_current_path());
        return optional_match;
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
bool expression::evaluator::eval_condition(const condition &cond, condition::cache_type &cond_cache)
{
    if (cond_cache.result.has_value()) {
        return true;
    }

    const auto &processor = get_processor(cond);
    if (!processor) {
        DDWAF_DEBUG("Condition doesn't have a valid processor");
        return false;
    }

    for (std::size_t ti = 0; ti < cond.targets.size(); ++ti) {
        const auto &target = cond.targets[ti];

        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (cond_cache.targets.find(ti) != cond_cache.targets.end()) {
            continue;
        }

        // TODO: iterators could be cached to avoid reinitialisation
        const ddwaf_object *object = store.get_target(target.root);
        if (object == nullptr) {
            continue;
        }

        DDWAF_TRACE("Evaluating target %s", target.name.c_str());

        std::optional<event::match> optional_match;
        if (target.source == data_source::keys) {
            object::key_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(it, processor, target.transformers);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(it, processor, target.transformers);
        }

        if (!optional_match.has_value()) {
            continue;
        }

        cond_cache.targets.emplace(ti);

        optional_match->address = target.name;
        cond_cache.result = optional_match;

        DDWAF_TRACE("Target %s matched parameter value %s", target.name.c_str(),
            optional_match->resolved.c_str());

        return true;
    }

    return cond_cache.result.has_value();
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
        if (!eval_condition(*conditions[i], cond_cache)) {
            return false;
        }
    }
    return true;
}

bool expression::eval(cache_type &cache, const object_store &store,
    const std::unordered_set<const ddwaf_object *> &objects_excluded,
    const std::unordered_map<std::string, operation::base::ptr> &dynamic_processors,
    ddwaf::timer &deadline) const
{
    // TODO the cache result alone might be insufficient
    if (!cache.result) {
        evaluator runner{
            deadline, limits_, conditions_, store, objects_excluded, dynamic_processors, cache};
        cache.result = runner.eval();
    }

    return cache.result;
}

memory::vector<event::match> expression::get_matches(cache_type &cache)
{
    if (!cache.result) {
        return {};
    }

    memory::vector<event::match> matches;
    for (auto cond_cache : cache.conditions) {
        // clang-tidy has trouble with an optional after two levels of indirection
        auto &result = cond_cache.result;
        if (result.has_value()) {
            matches.emplace_back(std::move(result.value()));
        } else {
            // Bug
            return {};
        }
    }

    return matches;
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
