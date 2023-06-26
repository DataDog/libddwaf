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
    enum class match_type : uint8_t {resolved, scalar, object};

    struct target_type {
        address_scope scope{address_scope::global};

        // Global scope
        target_index root;
        std::string name;

        // Local scope
        std::size_t condition_index;
        match_type match{match_type::object};

        std::vector<std::string> key_path{};

        // Transformers
        std::vector<PW_TRANSFORM_ID> transformers{};
        data_source source{data_source::values};
    };

    struct condition {
        struct cache_type {
            memory::unordered_set<target_index> targets_evaluated;
            std::string resolved{};
            ddwaf_object *scalar{nullptr};
            ddwaf_object *object{nullptr};
        };

        std::vector<target_type> targets_;
        std::shared_ptr<rule_processor::base> processor_;
        std::string data_id_;
    };

    struct cache_type {
        explicit cache_type(std::size_t num_conditions) {
            conditions.reserve(num_conditions);
        }

        std::vector<condition::cache_type> conditions;
    };


    explicit expression(std::vector<condition> &&conditions, ddwaf::object_limits limits = ddwaf::object_limits()):
        limits_(limits), conditions_(std::move(conditions)) {}

    bool eval(const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded,
        const std::unordered_map<std::string, rule_processor::base::ptr> &dynamic_processors,
        ddwaf::timer &deadline) const;

protected:
    ddwaf::object_limits limits_;
    std::vector<condition> conditions_;
};

} // namespace ddwaf
