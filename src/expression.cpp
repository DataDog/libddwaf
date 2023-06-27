// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <expression.hpp>
#include <log.hpp>
#include <memory>

namespace ddwaf {

template <typename T>
std::optional<event::match> expression::eval_target(condition &cond, cache_type &cache, T &it,
    const rule_processor::base::ptr &processor, const std::vector<PW_TRANSFORM_ID> & /*transformers*/,
    ddwaf::timer &deadline) const
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != DDWAF_OBJ_STRING) {
            continue;
        }

        auto optional_match = processor->match_object(*it);
        if (!optional_match.has_value()) {
            continue;
        }

        if (!cond.dependents.scalar.empty()) {
            for (auto index : cond.dependents.scalar) {
                
        optional_match->key_path = std::move(it.get_current_path());
        // If this target matched, we can stop processing
        return optional_match;
    }

    return std::nullopt;
}


bool expression::eval_condition(std::size_t index, cache_type &cache, const object_store &store,
    const std::unordered_set<const ddwaf_object *> &objects_excluded,
    ddwaf::timer &deadline) const
{
    const auto &cond = conditions_[index];
    auto  &cond_cache = cache.condition_cache[index];

    for (const auto &target : cond.targets) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (target.scope == eval_scope::local ||
            cond_cache.targets.find(target.root) != cond_cache.targets.end()) {
            continue;
        }

        // TODO: iterators could be cached to avoid reinitialisation
        const auto *object = store.get_target(target.root);
        if (object == nullptr) {
            continue;
        }

        std::optional<event::match> optional_match;
        if (target.source == data_source::keys) {
            object::key_iterator it(object, target.key_path, objects_excluded, limits_);
            optional_match = eval_target(it, cond.processor, target.transformers, deadline);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits_);
            optional_match = eval_target(it, cond.processor, target.transformers, deadline);
        }

        if (optional_match.has_value()) {
            optional_match->address = target.name;

            DDWAF_TRACE("Target %s matched parameter value %s",
                target.name.c_str(), optional_match->resolved.c_str());

            cond_cache.result = optional_match;
            return true;
        }
    }

    return false;
}

bool expression::eval(cache_type &cache, const object_store &store,
    const std::unordered_set<const ddwaf_object *> &objects_excluded,
    ddwaf::timer &deadline) const
{
    for (std::size_t i = 0; i < conditions_.size(); ++i) {
        auto res = eval_condition(i, cache, store, objects_excluded, deadline);
    }

    return true;
}


expression::condition::condition(std::vector<expression::target_type> targets_,
        std::shared_ptr<rule_processor::base> processor_):
    targets(std::move(targets_)), processor(std::move(processor_))
{
    for (const auto &target : targets) {
        if (target.scope == expression::eval_scope::global) { continue; }

        switch(target.entity) {
        case expression::eval_entity::resolved:
            dependents.resolved.emplace(target.condition_index);
            break;
        case expression::eval_entity::scalar:
            dependents.scalar.emplace(target.condition_index);
            break;
        case expression::eval_entity::object:
            dependents.object.emplace(target.condition_index);
            break;
        }
    }
}


} // namespace ddwaf
