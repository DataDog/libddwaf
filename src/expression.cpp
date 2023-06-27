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
        // TODO set the root object only after returning
        cache.set_eval_entities(cond.index, *it, it.get_root_object(), last_result->resolved);

        bool chain_result = true;
        for (condition::index_type i = 0; i < cond.dependents.scalar.size(); ++i) {
            const auto &next_cond = conditions[i];
            if (!eval_condition(next_cond)) {
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

bool expression::evaluator::eval_condition(const condition &cond)
{
    auto &cond_cache = cache.get_condition_cache(cond.index);

    for (const auto &target : cond.targets) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (cond_cache.targets.find(target.root) != cond_cache.targets.end()) {
            continue;
        }

        // TODO: iterators could be cached to avoid reinitialisation
        const ddwaf_object *object = nullptr;
        if (target.scope == condition::eval_scope::global) {
            object = store.get_target(target.root);
            if (object == nullptr) {
                continue;
            }
        } else {
            object = cache.get_eval_entity(target.condition_index, target.entity);
        }

        std::optional<event::match> optional_match;
        if (target.source == condition::data_source::keys) {
            object::key_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(cond, it, cond.processor, target.transformers);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(cond, it, cond.processor, target.transformers);
        }

        if (!optional_match.has_value()) {
            continue;
        }

        optional_match->address = target.name;
        cond_cache.result = optional_match;

        bool chain_result = true;
        for (condition::index_type i = 0; i < cond.dependents.object.size(); ++i) {
            const auto &next_cond = conditions[i];
            if (!eval_condition(next_cond)) {
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
    for (const auto &cond : conditions) {
        if (!eval_condition(cond)) {
            return false;
        }
    }
    return true;
}

bool expression::eval(cache_type &cache, const object_store &store,
    const std::unordered_set<const ddwaf_object *> &objects_excluded, ddwaf::timer &deadline) const
{
    evaluator runner{deadline, limits_, conditions_, store, objects_excluded, cache};
    runner.eval();
    return true;
}

condition::condition(index_type index_, std::vector<target_type> targets_,
    std::shared_ptr<rule_processor::base> processor_)
    : index(index_), targets(std::move(targets_)), processor(std::move(processor_))
{
    for (const auto &target : targets) {
        if (target.scope == eval_scope::global) {
            continue;
        }

        switch (target.entity) {
        case eval_entity::resolved:
        case eval_entity::scalar:
            dependents.scalar.emplace(target.condition_index);
            break;
        case eval_entity::object:
            dependents.object.emplace(target.condition_index);
            break;
        }
    }
}

} // namespace ddwaf::experimental
