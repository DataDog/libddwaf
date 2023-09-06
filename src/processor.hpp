// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "expression.hpp"
#include "generator/base.hpp"
#include "object_store.hpp"
#include "utils.hpp"

namespace ddwaf {

class processor {
public:
    struct target_mapping {
        // TODO implement n:1 support
        target_index input;
        target_index output;
        std::string output_address;
    };

    struct cache_type {
        expression::cache_type expr_cache;
        std::unordered_set<target_index> generated;
    };

    processor(std::string id, std::shared_ptr<generator::base> generator,
        std::shared_ptr<expression> expr, std::vector<target_mapping> mappings,
        std::set<const scanner *> scanners, bool evaluate, bool output)
        : id_(std::move(id)), generator_(std::move(generator)), expr_(std::move(expr)),
          mappings_(std::move(mappings)), scanners_(std::move(scanners)), evaluate_(evaluate),
          output_(output)
    {}

    processor(const processor &) = delete;
    processor &operator=(const processor &) = delete;

    processor(processor &&rhs) noexcept = default;
    processor &operator=(processor &&rhs) noexcept = default;
    virtual ~processor() = default;

    virtual void eval(object_store &store, optional_ref<ddwaf_object> &derived, cache_type &cache,
        ddwaf::timer &deadline) const;

    [[nodiscard]] const std::string &get_id() const { return id_; }

protected:
    std::string id_;
    std::shared_ptr<generator::base> generator_;
    std::shared_ptr<expression> expr_;
    std::vector<target_mapping> mappings_;
    std::set<const scanner *> scanners_;
    bool evaluate_{false};
    bool output_{true};
};

} // namespace ddwaf
