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

class expression {
public:
    using ptr = std::shared_ptr<expression>;

    enum class data_source : uint8_t { values, keys };
    enum class eval_scope : uint8_t { global, local };
    enum class eval_entity : uint8_t { highlight, scalar, object };

    struct condition {
        using ptr = std::shared_ptr<condition>;

        struct cache_type {
            std::unordered_set<target_index> targets{};
            std::optional<event::match> result{std::nullopt};
        };

        struct target_type {
            eval_scope scope{eval_scope::global};
            std::string name;

            // Global scope
            target_index root;

            // Local scope
            const condition *parent{nullptr};
            eval_entity entity{eval_entity::object};

            // Applicable to either scope
            std::vector<std::string> key_path{};

            // Transformers
            std::vector<PW_TRANSFORM_ID> transformers{};
            data_source source{data_source::values};
        };

        std::vector<target_type> targets;
        std::shared_ptr<rule_processor::base> processor;
        struct {
            std::unordered_set<const condition *> scalar{};
            std::unordered_set<const condition *> object{};
        } children;
    };

    struct eval_result {
        ddwaf_object highlight{nullptr, 0, {nullptr}, 0, DDWAF_OBJ_INVALID};
        const ddwaf_object *scalar{nullptr};
        const ddwaf_object *object{nullptr};
    };

    struct cache_type {
        std::unordered_map<const condition *, condition::cache_type> conditions{};
        std::unordered_map<const condition *, eval_result> store{};

        condition::cache_type &get_condition_cache(const condition &cond)
        {
            return conditions[&cond];
        }

        void set_eval_highlight(const condition *cond, const memory::string &str)
        {
            auto &res = store[cond];
            ddwaf_object_stringl_nc(&res.highlight, str.c_str(), str.size());
        }

        void set_eval_scalar(const condition *cond, const ddwaf_object *obj)
        {
            store[cond].scalar = obj;
        }

        void set_eval_object(const condition *cond, const ddwaf_object *obj)
        {
            store[cond].object = obj;
        }

        const ddwaf_object *get_eval_entity(const condition *cond, eval_entity entity)
        {
            auto it = store.find(cond);
            if (it != store.end()) {
                switch (entity) {
                case eval_entity::highlight:
                    return &it->second.highlight;
                case eval_entity::scalar:
                    return it->second.scalar;
                case eval_entity::object:
                    return it->second.object;
                }
            }
            return nullptr;
        }
    };

    struct evaluator {
        bool eval();
        bool eval_condition(const condition &cond, eval_scope scope);

        template <typename T>
        std::optional<event::match> eval_target(const condition &cond, T &it,
            const rule_processor::base::ptr &processor,
            const std::vector<PW_TRANSFORM_ID> & /*transformers*/);

        ddwaf::timer &deadline;
        const ddwaf::object_limits &limits;
        const std::vector<condition::ptr> &conditions;
        const object_store &store;
        const std::unordered_set<const ddwaf_object *> &objects_excluded;
        cache_type &cache;
    };

    explicit expression(std::vector<condition::ptr> &&conditions,
        ddwaf::object_limits limits = ddwaf::object_limits())
        : limits_(limits), conditions_(std::move(conditions))
    {}

    bool eval(cache_type &cache, const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded,
        ddwaf::timer &deadline) const;

protected:
    ddwaf::object_limits limits_;
    std::vector<condition::ptr> conditions_;
};

class expression_builder {
public:
    expression_builder() = default;

protected:
};

} // namespace ddwaf::experimental
