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
#include "matcher/base.hpp"
#include "monitor.hpp"
#include "object_store.hpp"
#include "rule/base.hpp"
#include "sliding_window_counter.hpp"

namespace ddwaf {

class threshold_rule : public base_threshold_rule {
public:
    struct evaluation_criteria {
        uint64_t threshold;
        std::chrono::milliseconds period{};
    };

    threshold_rule(std::string id, std::string name,
        std::unordered_map<std::string, std::string> tags, std::shared_ptr<expression> expr,
        evaluation_criteria criteria, std::vector<std::string> actions = {}, bool enabled = true)
        : base_threshold_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled),
          criteria_(criteria), counter_(criteria_.period, criteria_.threshold * 2),
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
    monitor<sliding_window_counter_ms> counter_;
    std::string threshold_str_;
};

class indexed_threshold_rule : public base_threshold_rule {
public:
    struct evaluation_criteria {
        std::string name;
        target_index target;
        uint64_t threshold;
        std::chrono::milliseconds period;
    };

    indexed_threshold_rule(std::string id, std::string name,
        std::unordered_map<std::string, std::string> tags, std::shared_ptr<expression> expr,
        evaluation_criteria criteria, std::vector<std::string> actions = {}, bool enabled = true)
        : base_threshold_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled),
          criteria_(std::move(criteria)), counter_(criteria_.period, 128, criteria_.threshold * 2),
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
    evaluation_criteria criteria_;
    monitor<indexed_sliding_window_counter_ms> counter_;
    std::string threshold_str_;
};

} // namespace ddwaf
