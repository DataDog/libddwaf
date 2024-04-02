// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <atomic>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "clock.hpp"
#include "event.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "iterator.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"

namespace ddwaf {

class threshold_rule {
public:
    using cache_type = expression::cache_type;

    threshold_rule(std::string id, std::string name, std::unordered_map<std::string, std::string> tags,
        std::shared_ptr<expression> expr, uint64_t threshold, const std::chrono::milliseconds &period,
        std::vector<std::string> actions = {}, bool enabled = true) 
        : enabled_(enabled), id_(std::move(id)), name_(std::move(name)),
          tags_(std::move(tags)), expr_(std::move(expr)), threshold_(threshold),
          period_(period), actions_(std::move(actions))
    {
        if (!expr_) {
            throw std::invalid_argument("threshold rule constructed with null expression");
        }
    }
    ~threshold_rule() = default;
    threshold_rule(const threshold_rule &) = delete;
    threshold_rule &operator=(const threshold_rule &) = delete;
    threshold_rule(threshold_rule &&rhs) noexcept = default;
    threshold_rule &operator=(threshold_rule &&rhs) noexcept = default;

protected:
    bool enabled_{true};
    std::string id_;
    std::string name_;
    std::unordered_map<std::string, std::string> tags_;
    std::shared_ptr<expression> expr_;
    uint64_t threshold_;
    std::chrono::milliseconds period_;
    std::vector<std::string> actions_;
};

} // namespace ddwaf
