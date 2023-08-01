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
#include <utility>
#include <vector>

#include "clock.hpp"
#include "context_allocator.hpp"
#include "event.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "object_store.hpp"
#include "operation/base.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

namespace ddwaf {

class expression {
public:
    using ptr = std::shared_ptr<expression>;

    enum class data_source : uint8_t { values, keys };

    struct condition {
        using ptr = std::unique_ptr<condition>;

        struct cache_type {
            bool result{false};
            memory::unordered_set<target_index> targets{};
            std::optional<event::match> match;
        };

        struct target_type {
            std::string name;
            target_index root{};
            std::vector<std::string> key_path{};
            std::vector<transformer_id> transformers{};
            data_source source{data_source::values};
        };

        std::vector<target_type> targets;
        operation::base::ptr processor;
        std::string data_id;
    };

    struct cache_type {
        bool result{false};
        memory::vector<event::match> matches{};
        std::optional<std::vector<condition::ptr>::const_iterator> last_cond{};
    };

    struct evaluator {
        bool eval();
        std::optional<event::match> eval_condition(const condition &cond, bool run_on_new);

        template <typename T>
        std::optional<event::match> eval_target(T &it, const operation::base::ptr &processor,
            const std::vector<transformer_id> &transformers);

        std::optional<event::match> eval_object(const ddwaf_object *object,
            const operation::base::ptr &processor,
            const std::vector<transformer_id> &transformers) const;

        [[nodiscard]] const operation::base::ptr &get_processor(const condition &cond) const;

        ddwaf::timer &deadline;
        const ddwaf::object_limits &limits;
        const std::vector<condition::ptr> &conditions;
        const object_store &store;
        const std::unordered_set<const ddwaf_object *> &objects_excluded;
        const std::unordered_map<std::string, operation::base::ptr> &dynamic_processors;
        cache_type &cache;
    };

    explicit expression(std::vector<condition::ptr> &&conditions, ddwaf::object_limits limits = {})
        : limits_(limits), conditions_(std::move(conditions))
    {}

    bool eval(cache_type &cache, const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded,
        const std::unordered_map<std::string, operation::base::ptr> &dynamic_processors,
        ddwaf::timer &deadline) const;

    void get_addresses(std::unordered_set<std::string> &addresses) const
    {
        for (const auto &cond : conditions_) {
            for (const auto &target : cond->targets) { addresses.emplace(target.name); }
        }
    }

    static memory::vector<event::match> &&get_matches(cache_type &cache)
    {
        return std::move(cache.matches);
    }

    static bool get_result(cache_type &cache) { return cache.result; }

    // For testing
    [[nodiscard]] std::size_t get_num_conditions() const { return conditions_.size(); }

protected:
    ddwaf::object_limits limits_;
    std::vector<condition::ptr> conditions_;
};

class expression_builder {
public:
    explicit expression_builder(std::size_t num_conditions, ddwaf::object_limits limits = {})
        : limits_(limits)
    {
        conditions_.reserve(num_conditions);
    }

    void start_condition() { conditions_.emplace_back(std::make_unique<expression::condition>()); }
    template <typename T, typename... Args> void start_condition(Args... args)
    {
        auto cond = std::make_unique<expression::condition>();
        cond->processor = std::make_shared<T>(std::forward<Args>(args)...);
        conditions_.emplace_back(std::move(cond));
    }

    void start_condition(std::string data_id)
    {
        auto cond = std::make_unique<expression::condition>();
        cond->data_id = std::move(data_id);
        conditions_.emplace_back(std::move(cond));
    }

    void set_data_id(std::string data_id)
    {
        auto &cond = conditions_.back();
        cond->data_id = std::move(data_id);
    }

    template <typename T, typename... Args> void set_processor(Args... args)
    {
        auto &cond = conditions_.back();
        cond->processor = std::make_shared<T>(args...);
    }

    void set_processor(operation::base::ptr &&processor)
    {
        auto &cond = conditions_.back();
        cond->processor = std::move(processor);
    }

    void add_target(std::string name, std::vector<std::string> key_path = {},
        std::vector<transformer_id> transformers = {},
        expression::data_source source = expression::data_source::values);

    expression::ptr build()
    {
        return std::make_shared<expression>(std::move(conditions_), limits_);
    }

protected:
    ddwaf::object_limits limits_;
    std::vector<expression::condition::ptr> conditions_;
};

} // namespace ddwaf
