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

std::optional<event::match> expression::evaluator::eval_object(const ddwaf_object *object,
    const rule_processor::base::ptr &processor,
    const std::vector<PW_TRANSFORM_ID> &transformers) const
{
    const bool has_transform = !transformers.empty();
    bool transform_required = false;

    if (has_transform) {
        // This codepath is shared with the mutable path. The structure can't be const :/
        transform_required =
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
            PWTransformer::doesNeedTransform(transformers, const_cast<ddwaf_object *>(object));
    }

    const size_t length =
        find_string_cutoff(object->stringValue, object->nbEntries, limits.max_string_length);

    // If we don't have transform to perform, or if they're irrelevant, no need to waste time
    // copying and allocating data
    if (!has_transform || !transform_required) {
        return processor->match({object->stringValue, length});
    }

    ddwaf_object copy;
    ddwaf_object_stringl(&copy, (const char *)object->stringValue, length);

    const std::unique_ptr<ddwaf_object, decltype(&ddwaf_object_free)> scope(
        &copy, ddwaf_object_free);

    // Transform it and pick the pointer to process
    bool transformFailed = false;
    for (const PW_TRANSFORM_ID &transform : transformers) {
        transformFailed = !PWTransformer::transform(transform, &copy);
        if (transformFailed || (copy.type == DDWAF_OBJ_STRING && copy.nbEntries == 0)) {
            break;
        }
    }

    if (transformFailed) {
        return processor->match({object->stringValue, length});
    }

    return processor->match_object(&copy);
}

template <typename T>
std::optional<event::match> expression::evaluator::eval_target(const condition &cond, T &it,
    const rule_processor::base::ptr &processor, const std::vector<PW_TRANSFORM_ID> &transformers)
{
    std::optional<event::match> last_result = std::nullopt;

    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != DDWAF_OBJ_STRING) {
            continue;
        }

        auto optional_match = eval_object(*it, processor, transformers);
        if (!optional_match.has_value()) {
            continue;
        }

        last_result = std::move(optional_match);
        last_result->key_path = std::move(it.get_current_path());

        if (cond.children.scalar.empty()) {
            break;
        }

        cache.set_eval_highlight(&cond, last_result->matched);
        cache.set_eval_scalar(&cond, *it);

        bool chain_result = true;
        for (const auto *next_cond : cond.children.scalar) {
            if (!eval_condition(*next_cond, eval_scope::local)) {
                chain_result = false;
                break;
            }
        }

        if (chain_result) {
            break;
        }
    }

    return last_result;
}

// NOLINTNEXTLINE(misc-no-recursion)
bool expression::evaluator::eval_condition(const condition &cond, eval_scope scope)
{
    auto &cond_cache = cache.get_condition_cache(cond);

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
        if (target.scope == eval_scope::global) {
            object = store.get_target(target.root);
        } else {
            object = cache.get_eval_entity(target.parent, target.entity);
        }

        if (object == nullptr) {
            continue;
        }

        std::optional<event::match> optional_match;
        if (target.source == data_source::keys) {
            object::key_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(cond, it, cond.processor, target.transformers);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(cond, it, cond.processor, target.transformers);
        }

        // Only cache global targets
        if (target.scope == eval_scope::global) {
            cond_cache.targets.emplace(target.root);
        }

        if (!optional_match.has_value()) {
            continue;
        }

        optional_match->address = target.name;
        cond_cache.result = optional_match;

        if (!cond.children.object.empty()) {
            cache.set_eval_object(&cond, object);

            bool chain_result = true;
            for (const auto *next_cond : cond.children.object) {
                if (!eval_condition(*next_cond, eval_scope::local)) {
                    chain_result = false;
                    break;
                }
            }

            if (!chain_result) {
                continue;
            }
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
        if (!eval_condition(*cond, eval_scope::global)) {
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
