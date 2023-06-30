// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <charconv>
#include <exception.hpp>
#include <expression.hpp>
#include <log.hpp>
#include <memory>

namespace ddwaf {

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

        DDWAF_TRACE("Value %s", (*it)->stringValue);
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

const rule_processor::base::ptr &expression::evaluator::get_processor(const condition &cond) const
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
bool expression::evaluator::eval_condition(const condition &cond, eval_scope scope)
{
    auto &cond_cache = cache.get_condition_cache(cond);

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

        if (scope != target.scope || cond_cache.targets.find(ti) != cond_cache.targets.end()) {
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

        DDWAF_TRACE("Evaluating target %s", target.name.c_str());

        std::optional<event::match> optional_match;
        if (target.source == data_source::keys) {
            object::key_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(cond, it, processor, target.transformers);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(cond, it, processor, target.transformers);
        }

        if (!optional_match.has_value()) {
            continue;
        }

        cond_cache.targets.emplace(ti);

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

    return cond_cache.result.has_value();
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
    const std::unordered_set<const ddwaf_object *> &objects_excluded,
    const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
    ddwaf::timer &deadline) const
{
    if (cache.conditions.size() != conditions_.size()) {
        cache.conditions.reserve(conditions_.size());
        cache.store.reserve(conditions_.size());
    }

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

    for (const auto &cond : conditions_) {
        auto it = cache.conditions.find(cond.get());
        if (it == cache.conditions.end()) {
            // Bug
            return {};
        }

        auto &cond_cache = it->second;

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

namespace {
std::tuple<bool, std::size_t, expression::eval_entity> explode_local_address(std::string_view str)
{
    constexpr std::string_view prefix = "match.";
    auto pos = str.find(prefix);
    if (pos == std::string_view::npos) {
        return {false, 0, {}};
    }
    str.remove_prefix(prefix.size());

    // TODO everything below this point should throw instead of returning false
    pos = str.find('.');
    if (pos == std::string_view::npos) {
        return {false, 0, {}};
    }

    auto index_str = str.substr(0, pos);
    std::size_t index = 0;
    auto result = std::from_chars(index_str.data(), index_str.data() + index_str.size(), index);
    if (result.ec == std::errc::invalid_argument) {
        return {false, 0, {}};
    }

    expression::eval_entity entity;
    auto entity_str = str.substr(pos + 1, str.size() - (pos + 1));
    if (entity_str == "object") {
        entity = expression::eval_entity::object;
    } else if (entity_str == "scalar") {
        entity = expression::eval_entity::scalar;
    } else if (entity_str == "highlight") {
        entity = expression::eval_entity::highlight;
    } else {
        return {false, 0, {}};
    }

    return {true, index, entity};
}

} // namespace
  //
void expression_builder::add_target(std::string name, std::vector<std::string> key_path,
    std::vector<PW_TRANSFORM_ID> transformers, expression::data_source source)
{
    auto [res, index, entity] = explode_local_address(name);
    if (res) {
        add_local_target(
            std::move(name), index, entity, std::move(key_path), std::move(transformers), source);
    } else {
        add_global_target(std::move(name), std::move(key_path), std::move(transformers), source);
    }
}

void expression_builder::add_global_target(std::string name, std::vector<std::string> key_path,
    std::vector<PW_TRANSFORM_ID> transformers, expression::data_source source)
{
    expression::condition::target_type target;
    target.scope = expression::eval_scope::global;
    target.root = get_target_index(name);
    target.key_path = std::move(key_path);
    target.name = std::move(name);
    target.transformers = std::move(transformers);
    target.source = source;

    auto &cond = conditions_.back();
    cond->targets.emplace_back(std::move(target));
}

void expression_builder::add_local_target(std::string name, std::size_t cond_idx,
    expression::eval_entity entity, std::vector<std::string> key_path,
    std::vector<PW_TRANSFORM_ID> transformers, expression::data_source source)
{
    if (cond_idx >= (conditions_.size() - 1)) {
        throw std::invalid_argument(
            "local target references subsequent condition (or itself): current = " +
            std::to_string(conditions_.size() - 1) + ", referenced = " + std::to_string(cond_idx));
    }

    auto &parent = conditions_[cond_idx];
    auto &cond = conditions_.back();

    if (entity == expression::eval_entity::object) {
        parent->children.object.emplace(cond.get());
    } else {
        parent->children.scalar.emplace(cond.get());
    }

    expression::condition::target_type target;
    target.scope = expression::eval_scope::local;
    target.parent = parent.get();
    target.entity = entity;
    target.key_path = std::move(key_path);
    target.name = std::move(name);
    target.transformers = std::move(transformers);
    target.source = source;

    cond->targets.emplace_back(std::move(target));
}

} // namespace ddwaf
