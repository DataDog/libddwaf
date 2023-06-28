// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "log.hpp"
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

namespace ddwaf::experimental {

struct condition {
    using ptr = std::shared_ptr<condition>;
    using index_type = std::size_t;

    struct cache_type {
        std::unordered_set<target_index> targets{};
        std::optional<event::match> result{std::nullopt};
    };

    enum class data_source : uint8_t { values, keys };
    enum class eval_scope : uint8_t { global, local };
    enum class eval_entity : uint8_t { resolved, scalar, object };

    struct target_type {
        eval_scope scope{eval_scope::global};
        std::string name;

        // Global scope
        target_index root;

        // Local scope
        std::size_t condition_index{0};
        eval_entity entity{eval_entity::object};

        // Applicable to either scope
        std::vector<std::string> key_path{};

        // Transformers
        std::vector<PW_TRANSFORM_ID> transformers{};
        data_source source{data_source::values};
    };

    index_type index;
    std::vector<target_type> targets;
    std::shared_ptr<rule_processor::base> processor;
    struct {
        std::unordered_set<std::size_t> scalar{};
        std::unordered_set<std::size_t> object{};
    } dependents;
};

class expression {
public:
    using ptr = std::shared_ptr<expression>;

    struct eval_result {
        ddwaf_object resolved{nullptr, 0, {nullptr}, 0, DDWAF_OBJ_INVALID};
        const ddwaf_object *scalar{nullptr};
        const ddwaf_object *object{nullptr};
    };

    struct cache_type {
        std::unordered_map<std::size_t, condition::cache_type> conditions{};
        std::unordered_map<std::size_t, eval_result> store{};

        condition::cache_type &get_condition_cache(condition::index_type index)
        {
            return conditions[index];
        }

        void set_eval_resolved(condition::index_type index, const memory::string &str)
        {
            ddwaf_object_stringl_nc(&store[index].resolved, str.c_str(), str.size());
        }

        void set_eval_scalar(condition::index_type index, const ddwaf_object *obj)
        {
            store[index].scalar = obj;
        }

        void set_eval_object(condition::index_type index, const ddwaf_object *obj)
        {
            store[index].object = obj;
        }

        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
        void set_eval_entities(condition::index_type index, const ddwaf_object *scalar,
            const ddwaf_object *object, const memory::string &resolved)
        {
            auto &eval_res = store[index];
            eval_res.scalar = scalar;
            DDWAF_TRACE("Object %p", object);
            eval_res.object = object;
            ddwaf_object_stringl_nc(&eval_res.resolved, resolved.c_str(), resolved.size());
        }

        const ddwaf_object *get_eval_entity(
            condition::index_type index, condition::eval_entity entity)
        {
            auto it = store.find(index);
            if (it != store.end()) {
                if (entity == condition::eval_entity::resolved) {
                    return &it->second.resolved;
                }

                if (entity == condition::eval_entity::scalar) {
                    return it->second.scalar;
                }

                if (entity == condition::eval_entity::object) {
                    return it->second.object;
                }
            }

            return nullptr;
        }
    };

    struct evaluator {
        bool eval();
        bool eval_condition(const condition &cond, condition::eval_scope scope);

        template <typename T>
        std::optional<event::match> eval_target(const condition &cond, T &it,
            const rule_processor::base::ptr &processor,
            const std::vector<PW_TRANSFORM_ID> & /*transformers*/);

        ddwaf::timer &deadline;
        const ddwaf::object_limits &limits;
        const std::vector<condition> &conditions;
        const object_store &store;
        const std::unordered_set<const ddwaf_object *> &objects_excluded;
        cache_type &cache;
    };

    explicit expression(
        std::vector<condition> &&conditions, ddwaf::object_limits limits = ddwaf::object_limits())
        : limits_(limits), conditions_(std::move(conditions))
    {}

    bool eval(cache_type &cache, const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded,
        ddwaf::timer &deadline) const;

protected:
    template <typename T>
    std::optional<event::match> eval_target(T &it, const rule_processor::base::ptr &processor,
        const std::vector<PW_TRANSFORM_ID> &transformers, ddwaf::timer &deadline) const;

    bool eval_condition(std::size_t index, cache_type &cache, const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded,
        ddwaf::timer &deadline) const;

    ddwaf::object_limits limits_;
    std::vector<condition> conditions_;
};

} // namespace ddwaf::experimental
