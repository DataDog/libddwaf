// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include <PWTransformer.h>
#include <clock.hpp>
#include <context_allocator.hpp>
#include <event.hpp>
#include <iterator.hpp>
#include <object_store.hpp>
#include <rule_processor/base.hpp>

namespace ddwaf {

class expression {
public:
    using ptr = std::shared_ptr<expression>;

    enum class data_source : uint8_t { values, keys };
    enum class eval_scope : uint8_t { global, local };
    enum class eval_entity : uint8_t {resolved, scalar, object};

    struct target_type {
        eval_scope scope{eval_scope::global};
        std::string name;

        // Global scope
        target_index root;

        // Local scope
        std::size_t condition_index;
        eval_entity entity{eval_entity::object};

        // Applicable to either scope
        std::vector<std::string> key_path{};

        // Transformers
        std::vector<PW_TRANSFORM_ID> transformers{};
        data_source source{data_source::values};
    };

    struct condition {
        struct cache_type {
            memory::unordered_set<target_index> targets;
            std::optional<event::match> result;
        };

        condition(std::vector<expression::target_type> targets,
            std::shared_ptr<rule_processor::base> processor);

        std::vector<target_type> targets;
        std::shared_ptr<rule_processor::base> processor;
        struct {
            std::unordered_set<std::size_t> resolved{};
            std::unordered_set<std::size_t> scalar{};
            std::unordered_set<std::size_t> object{};
        } dependents;
    };

    struct eval_result {
        std::string resolved;
        const ddwaf_object *scalar;
        const ddwaf_object *object;
    };

    struct cache_type {
        memory::vector<condition::cache_type> condition_cache{};

        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
/*        void cache_result(std::size_t index, target_index target, std::optional<eval_result> &result) {*/
            /*if (index >= condition_cache.size()) { return; }*/

            /*if (result.has_value()) {*/
                /*results[index] = std::move(*result);*/
                /*condition_cache[index].result = true;*/
            /*}*/
            /*condition_cache[index].targets.emplace(target);*/
        /*}*/

        /*void invalidate(std::size_t index) {*/
            /*if (index >= condition_cache.size()) { return; }*/

            /*condition_cache[index].result = false;*/
            /*results[index] = {};*/
        /*}*/
    };

    explicit expression(std::vector<condition> &&conditions, ddwaf::object_limits limits = ddwaf::object_limits()):
        limits_(limits), conditions_(std::move(conditions)) {}

    bool eval(cache_type &cache, const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded,
        ddwaf::timer &deadline) const;

protected:

    template <typename T>
    std::optional<event::match> eval_target(condition &cond, cache_type &cache, T &it,
        const rule_processor::base::ptr &processor, const std::vector<PW_TRANSFORM_ID> &transformers,
        ddwaf::timer &deadline) const;

    bool eval_condition(std::size_t index, cache_type &cache, const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded,
        ddwaf::timer &deadline) const;

    ddwaf::object_limits limits_;
    std::vector<condition> conditions_;
};

} // namespace ddwaf
