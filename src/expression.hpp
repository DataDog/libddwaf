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
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "log.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "transformer/manager.hpp"
#include "utils.hpp"

namespace ddwaf {

class expression {
public:
    enum class data_source : uint8_t { values, keys };

    struct eval_result {
        bool outcome;
        bool ephemeral;
    };

    struct condition {

        struct cache_type {
            memory::vector<ddwaf_object *> targets;
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
        std::unique_ptr<matcher::base> matcher;
        std::string data_id;
    };

    struct cache_type {
        bool result{false};
        memory::vector<condition::cache_type> conditions;
    };

    struct evaluator {
        eval_result eval();

        eval_result eval_condition(const condition &cond, condition::cache_type &cache);

        template <typename T>
        std::optional<event::match> eval_target(
            T &it, const matcher::base &matcher, const std::vector<transformer_id> &transformers);

        std::optional<event::match> eval_object(const ddwaf_object *object,
            const matcher::base &matcher, const std::vector<transformer_id> &transformers) const;

        [[nodiscard]] const matcher::base *get_matcher(const condition &cond) const;

        ddwaf::timer &deadline;
        const ddwaf::object_limits &limits;
        const std::vector<condition> &conditions;
        const object_store &store;
        const std::unordered_set<const ddwaf_object *> &objects_excluded;
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers;
        cache_type &cache;
    };

    expression() = default;

    explicit expression(std::vector<condition> &&conditions, ddwaf::object_limits limits = {})
        : limits_(limits), conditions_(std::move(conditions))
    {}

    eval_result eval(cache_type &cache, const object_store &store,
        const std::unordered_set<const ddwaf_object *> &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        ddwaf::timer &deadline) const;

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const
    {
        for (const auto &cond : conditions_) {
            for (const auto &target : cond.targets) { addresses.emplace(target.root, target.name); }
        }
    }

    static memory::vector<event::match> get_matches(cache_type &cache)
    {
        memory::vector<event::match> matches;
        matches.reserve(cache.conditions.size());
        for (auto &cond_cache : cache.conditions) {
            auto &match = cond_cache.match;
            if (match.has_value()) {
                if (match->ephemeral) {
                    matches.emplace_back(std::move(match.value()));
                } else {
                    matches.emplace_back(match.value());
                }
            }
        }
        return matches;
    }

    static bool get_result(cache_type &cache) { return cache.result; }

    [[nodiscard]] bool empty() const { return conditions_.empty(); }
    [[nodiscard]] std::size_t size() const { return conditions_.size(); }

protected:
    ddwaf::object_limits limits_;
    std::vector<condition> conditions_;
};

class expression_builder {
public:
    explicit expression_builder(std::size_t num_conditions, ddwaf::object_limits limits = {})
        : limits_(limits)
    {
        conditions_.reserve(num_conditions);
    }

    void start_condition() { conditions_.emplace_back(expression::condition{}); }
    template <typename T, typename... Args> void start_condition(Args... args)
    {
        expression::condition cond;
        cond.matcher = std::make_unique<T>(std::forward<Args>(args)...);
        conditions_.emplace_back(std::move(cond));
    }

    void start_condition(std::string data_id)
    {
        expression::condition cond;
        cond.data_id = std::move(data_id);
        conditions_.emplace_back(std::move(cond));
    }

    void set_data_id(std::string data_id)
    {
        auto &cond = conditions_.back();
        cond.data_id = std::move(data_id);
    }

    template <typename T, typename... Args> void set_matcher(Args... args)
    {
        auto &cond = conditions_.back();
        cond.matcher = std::make_unique<T>(args...);
    }

    void set_matcher(std::unique_ptr<matcher::base> &&matcher)
    {
        auto &cond = conditions_.back();
        cond.matcher = std::move(matcher);
    }

    void add_target(std::string name, std::vector<std::string> key_path = {},
        std::vector<transformer_id> transformers = {},
        expression::data_source source = expression::data_source::values);

    std::shared_ptr<expression> build()
    {
        return std::make_shared<expression>(std::move(conditions_), limits_);
    }

protected:
    ddwaf::object_limits limits_{};
    std::vector<expression::condition> conditions_{};
};

} // namespace ddwaf
