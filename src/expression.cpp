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
#include "utils.hpp"

namespace ddwaf {

namespace {

// TODO store as std::variant<memory::string, bool, int64_t, uint64_t>?
memory::string object_to_string(const ddwaf_object &object)
{
    if (object.type == DDWAF_OBJ_STRING) {
        return memory::string{object.stringValue, static_cast<std::size_t>(object.nbEntries)};
    }

    if (object.type == DDWAF_OBJ_BOOL) {
        return to_string<memory::string>(object.boolean);
    }

    if (object.type == DDWAF_OBJ_SIGNED) {
        return to_string<memory::string>(object.intValue);
    }

    if (object.type == DDWAF_OBJ_UNSIGNED) {
        return to_string<memory::string>(object.uintValue);
    }

    return {};
}

} // namespace

std::optional<event::match> expression::evaluator::eval_object(const ddwaf_object *object,
    const operation::base &processor, const std::vector<transformer_id> &transformers) const
{
    ddwaf_object src = *object;

    if (object->type == DDWAF_OBJ_STRING) {
        src.nbEntries = find_string_cutoff(src.stringValue, src.nbEntries, limits);
        if (!transformers.empty()) {
            ddwaf_object dst;
            ddwaf_object_invalid(&dst);

            auto transformed = transformer::manager::transform(src, dst, transformers);
            scope_exit on_exit([&dst] { ddwaf_object_free(&dst); });
            if (transformed) {
                auto [res, highlight] = processor.match(dst);
                if (!res) {
                    return std::nullopt;
                }
                return {{object_to_string(dst), std::move(highlight), processor.name(),
                    processor.to_string(), {}, {}}};
            }
        }
    }

    auto [res, highlight] = processor.match(src);
    if (!res) {
        return std::nullopt;
    }

    return {{object_to_string(src), std::move(highlight), processor.name(), processor.to_string(),
        {}, {}}};
}

template <typename T>
std::optional<event::match> expression::evaluator::eval_target(
    T &it, const operation::base &processor, const std::vector<transformer_id> &transformers)
{
    for (; it; ++it) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (it.type() != processor.supported_type()) {
            continue;
        }

        auto optional_match = eval_object(*it, processor, transformers);
        if (!optional_match.has_value()) {
            continue;
        }

        optional_match->key_path = std::move(it.get_current_path());
        // If this target matched, we can stop processing
        return optional_match;
    }

    return std::nullopt;
}

const operation::base *expression::evaluator::get_processor(const condition &cond) const
{
    if (cond.processor || cond.data_id.empty()) {
        return cond.processor.get();
    }

    auto it = dynamic_processors.find(cond.data_id);
    if (it == dynamic_processors.end()) {
        return cond.processor.get();
    }

    return it->second.get();
}

// NOLINTNEXTLINE(misc-no-recursion)
std::optional<event::match> expression::evaluator::eval_condition(
    const condition &cond, bool run_on_new)
{
    const auto *processor = get_processor(cond);
    if (processor == nullptr) {
        DDWAF_DEBUG("Condition doesn't have a valid processor");
        return std::nullopt;
    }

    for (const auto &target : cond.targets) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (run_on_new && !store.is_new_target(target.root)) {
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
            optional_match = eval_target(it, *processor, target.transformers);
        } else {
            object::value_iterator it(object, target.key_path, objects_excluded, limits);
            optional_match = eval_target(it, *processor, target.transformers);
        }

        if (optional_match.has_value()) {
            optional_match->address = target.name;
            DDWAF_TRACE("Target %s matched parameter value %s", target.name.c_str(),
                optional_match->resolved.c_str());

            return optional_match;
        }
    }

    return std::nullopt;
}

bool expression::evaluator::eval()
{
    // On the first run, go through the conditions. Stop either at the first
    // condition that didn't match and return no event or go through all
    // and return an event.
    // On subsequent runs, we can start at the first condition that did not
    // match, because if the conditions matched with the data of the first
    // run, then they having new data will make them match again. The condition
    // that failed (and stopped the processing), we can run it again, but only
    // on the new data. The subsequent conditions, we need to run with all data.
    std::vector<condition::ptr>::const_iterator cond_iter;
    bool run_on_new;
    if (cache.last_cond.has_value()) {
        cond_iter = *cache.last_cond;
        run_on_new = true;
    } else {
        cond_iter = conditions.cbegin();
        run_on_new = false;
    }

    while (cond_iter != conditions.cend()) {
        auto &&cond = *cond_iter;
        auto optional_match = eval_condition(*cond, run_on_new);
        if (!optional_match.has_value()) {
            cache.last_cond = cond_iter;
            return false;
        }

        cache.matches.emplace_back(std::move(*optional_match));

        run_on_new = false;
        cond_iter++;
    }

    return true;
}

bool expression::eval(cache_type &cache, const object_store &store,
    const std::unordered_set<const ddwaf_object *> &objects_excluded,
    const std::unordered_map<std::string, operation::base::shared_ptr> &dynamic_processors,
    ddwaf::timer &deadline) const
{
    if (cache.result || conditions_.empty()) {
        return true;
    }

    evaluator runner{
        deadline, limits_, conditions_, store, objects_excluded, dynamic_processors, cache};
    return (cache.result = runner.eval());
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