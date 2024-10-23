// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "clock.hpp"
#include "event.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "lru_cache.hpp"
#include "matcher/base.hpp"
#include "monitor.hpp"
#include "object_store.hpp"
#include "rule/base.hpp"
#include "sliding_window_counter.hpp"

namespace ddwaf {

class threshold_counter {
public:
    threshold_counter(std::chrono::milliseconds period, uint64_t threshold,
        std::chrono::milliseconds threshold_duration)
        : threshold_(threshold), counter_{period, threshold * 2},
          threshold_duration_(threshold_duration)
    {}

    bool add_timepoint_and_count(std::chrono::milliseconds ms)
    {
        if (expiration_ > ms) {
            return true;
        }

        auto count = counter_.add_timepoint_and_count(ms);
        if (count > threshold_) {
            expiration_ = ms + threshold_duration_;
            return true;
        }

        return false;
    }

protected:
    uint64_t threshold_;
    sliding_window_counter_ms counter_;
    std::chrono::milliseconds threshold_duration_;
    std::chrono::milliseconds expiration_{0};
};

class threshold_rule : public base_threshold_rule {
public:
    struct evaluation_criteria {
        uint64_t threshold;
        std::chrono::milliseconds period{};
        std::chrono::milliseconds duration{};
    };

    threshold_rule(std::string id, std::string name,
        std::unordered_map<std::string, std::string> tags, std::shared_ptr<expression> expr,
        evaluation_criteria criteria, std::vector<std::string> actions = {}, bool enabled = true)
        : base_threshold_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled),
          criteria_(criteria),
          counter_(criteria_.period, criteria_.threshold * 2, criteria_.duration),
          threshold_str_(to_string<std::string>(criteria_.threshold))
    {}

    ~threshold_rule() override = default;
    threshold_rule(const threshold_rule &) = delete;
    threshold_rule &operator=(const threshold_rule &) = delete;
    threshold_rule(threshold_rule &&rhs) noexcept = delete;
    threshold_rule &operator=(threshold_rule &&rhs) noexcept = delete;

    std::optional<event> eval(const object_store &store, cache_type &cache,
        monotonic_clock::time_point now, ddwaf::timer &deadline) override;

protected:
    evaluation_criteria criteria_;
    monitor<threshold_counter> counter_;
    std::string threshold_str_;
};

class indexed_threshold_rule : public base_threshold_rule {
public:
    struct evaluation_criteria {
        uint64_t threshold;
        std::chrono::milliseconds period;
        std::chrono::milliseconds duration{};
        struct {
            std::string name;
            target_index target;
            std::vector<std::string> key_path;
            std::vector<transformer_id> transformers{};
            std::unique_ptr<matcher::base> matcher;
        } filter;
    };

    indexed_threshold_rule(std::string id, std::string name,
        std::unordered_map<std::string, std::string> tags, std::shared_ptr<expression> expr,
        evaluation_criteria criteria, std::vector<std::string> actions = {}, bool enabled = true)
        : base_threshold_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled),
          criteria_(std::move(criteria)),
          counter_cache_(threshold_counter_constructor{criteria_.period, criteria_.threshold,
                             criteria_.duration},
              128),
          threshold_str_(to_string<std::string>(criteria_.threshold))
    {}

    ~indexed_threshold_rule() override = default;
    indexed_threshold_rule(const indexed_threshold_rule &) = delete;
    indexed_threshold_rule &operator=(const indexed_threshold_rule &) = delete;
    indexed_threshold_rule(indexed_threshold_rule &&rhs) noexcept = delete;
    indexed_threshold_rule &operator=(indexed_threshold_rule &&rhs) noexcept = delete;

    std::optional<event> eval(const object_store &store, cache_type &cache,
        monotonic_clock::time_point now, ddwaf::timer &deadline) override;

protected:
    struct threshold_counter_constructor {
        std::chrono::milliseconds period;
        uint64_t threshold;
        std::chrono::milliseconds threshold_duration;

        threshold_counter operator()() const
        {
            return threshold_counter{period, threshold, threshold_duration};
        }
    };

    evaluation_criteria criteria_;
    lru_cache_ms<threshold_counter, threshold_counter_constructor> counter_cache_;
    std::string threshold_str_;
    std::mutex mtx_;
};

} // namespace ddwaf
