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
    enum class data_source : uint8_t { values, keys };
    enum class address_scope : uint8_t { global, local };
    enum class eval_target : uint8_t {resolved, scalar, object};

    struct target_type {
        address_scope scope{address_scope::global};
        std::string name;

        // Global scope
        struct {
            target_index root;
            std::vector<std::string> key_path{};
        } global;

        // Local scope
        struct {
            std::size_t index;
            eval_target target{eval_target::object};
        } local;

        // Transformers
        std::vector<PW_TRANSFORM_ID> transformers{};
        data_source source{data_source::values};
    };

    struct condition {
        struct cache_type {
            bool result{false};
            memory::unordered_set<target_index> evaluated_targets;
        };

        std::vector<target_type> targets;
        std::shared_ptr<rule_processor::base> processor;
    };

    struct eval_result {
        std::string resolved;
        const ddwaf_object *scalar;
        const ddwaf_object *object;
    };

    struct cache_type {
        std::vector<eval_result> results;
        memory::vector<condition::cache_type> condition_cache{};

        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
        void cache_result(std::size_t index, target_index target, std::optional<eval_result> &result) {
            if (index >= condition_cache.size()) { return; }

            if (result.has_value()) {
                results[index] = std::move(*result);
                condition_cache[index].result = true;
            }
            condition_cache[index].evaluated_targets.emplace(target);
        }

        void invalidate(std::size_t index) {
            if (index >= condition_cache.size()) { return; }

            condition_cache[index].result = false;
            results[index] = {};
        }
    };

    explicit expression(std::vector<condition> &&conditions, ddwaf::object_limits limits = ddwaf::object_limits()):
        limits_(limits), conditions_(std::move(conditions)) {}

    bool eval(cache_type &cache, const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded,
        ddwaf::timer &deadline) const;

protected:
    ddwaf::object_limits limits_;
    std::vector<condition> conditions_;
};

} // namespace ddwaf
