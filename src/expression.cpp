// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <expression.hpp>
#include <log.hpp>
#include <memory>

namespace ddwaf::experimental {

template <typename T>
std::optional<event::match> expression::evaluator::eval_target(const condition &cond, T &it,
    const rule_processor::base::ptr &processor,
    const std::vector<PW_TRANSFORM_ID> & /*transformers*/)
{
    std::optional<event::match> last_result = std::nullopt;

    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != DDWAF_OBJ_STRING) {
            continue;
        }

        {
            auto optional_match = processor->match_object(*it);
            if (!optional_match.has_value()) {
                continue;
            }
            last_result = std::move(optional_match);
        }

        last_result->key_path = std::move(it.get_current_path());
        cache.set_eval_highlight(cond.index, last_result->matched);
        cache.set_eval_scalar(cond.index, *it);

        bool chain_result = true;
        for (auto index : cond.dependents.scalar) {
            const auto &next_cond = conditions[index];
            if (!eval_condition(next_cond, condition::eval_scope::local)) {
                chain_result = false;
                break;
            }
        }

        if (!chain_result) {
            continue;
        }

        break;
    }

    return last_result;
}

// NOLINTNEXTLINE(misc-no-recursion)
bool expression::evaluator::eval_condition(const condition &cond, condition::eval_scope scope)
{
    auto &cond_cache = cache.get_condition_cache(cond.index);

    if (cond_cache.result.has_value()) {
        return true;
    }

    for (const auto &target : cond.targets) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (scope != target.scope ||
            cond_cache.targets.find(target.root) != cond_cache.targets.end()) {
            continue;
        }

        // TODO: iterators could be cached to avoid reinitialisation
        const ddwaf_object *object = nullptr;
        if (target.scope == condition::eval_scope::global) {
            object = store.get_target(target.root);
        } else {
            object = cache.get_eval_entity(target.condition_index, target.entity);
        }

        if (object == nullptr) {
            DDWAF_TRACE("No object found for target %s", target.name.c_str());
            continue;
        }

        DDWAF_TRACE("Original object %p", object);
        DDWAF_TRACE("Value %.*s", (int)object->nbEntries, object->stringValue);

        std::optional<event::match> optional_match;
        if (target.source == condition::data_source::keys) {
            object::key_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(cond, it, cond.processor, target.transformers);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(cond, it, cond.processor, target.transformers);
        }

        cond_cache.targets.emplace(target.root);

        if (!optional_match.has_value()) {
            continue;
        }

        optional_match->address = target.name;
        cond_cache.result = optional_match;

        cache.set_eval_object(cond.index, object);

        DDWAF_TRACE("Match! Checking chain");
        bool chain_result = true;
        for (auto index : cond.dependents.object) {
            const auto &next_cond = conditions[index];
            if (!eval_condition(next_cond, condition::eval_scope::local)) {
                DDWAF_TRACE("Chain %lu didn't match", index)
                chain_result = false;
                break;
            }
        }

        if (!chain_result) {
            continue;
        }

        DDWAF_TRACE("Target %s matched parameter value %s", target.name.c_str(),
            optional_match->resolved.c_str());

        return true;
    }

    return false;
}

bool expression::evaluator::eval()
{
    // NOLINTNEXTLINE(readability-use-anyofallof)
    for (const auto &cond : conditions) {
        DDWAF_TRACE("Condition %lu", cond.index);
        if (!eval_condition(cond, condition::eval_scope::global)) {
            return false;
        }
    }
    return true;
}

bool expression::eval(cache_type &cache, const object_store &store,
    const std::unordered_set<const ddwaf_object *> &objects_excluded, ddwaf::timer &deadline) const
{
    if (cache.conditions.size() != conditions_.size()) {
        cache.conditions.reserve(conditions_.size());
        cache.store.reserve(conditions_.size());
    }

    evaluator runner{deadline, limits_, conditions_, store, objects_excluded, cache};
    return runner.eval();
}

} // namespace ddwaf::experimental
