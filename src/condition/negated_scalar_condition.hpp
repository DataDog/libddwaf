// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/base.hpp"

namespace ddwaf {

class negated_scalar_condition : public base_condition {
public:
    negated_scalar_condition(std::unique_ptr<matcher::base> &&matcher, std::string data_id,
        std::vector<condition_parameter> args)
        : matcher_(std::move(matcher)), data_id_(std::move(data_id))
    {
        if (args.size() > 1) {
            throw std::invalid_argument("matcher initialised with more than one argument");
        }

        if (args.empty()) {
            throw std::invalid_argument("matcher initialised without arguments");
        }

        if (args[0].targets.size() > 1) {
            throw std::invalid_argument("negated matchers don't support variadic arguments");
        }

        target_ = std::move(args[0].targets[0]);
    }

    eval_result eval(base_cache_type &cache, const object_store &store,
        const object_set_ref &objects_excluded, const matcher_mapper &dynamic_matchers,
        ddwaf::timer &deadline) const override;

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const override
    {
        addresses.emplace(target_.index, target_.name);
    }

    static constexpr auto arguments()
    {
        return std::array<parameter_specification, 1>{
            {{.name = "inputs", .variadic = false, .optional = false}}};
    }

protected:
    std::unique_ptr<matcher::base> matcher_;
    std::string data_id_;
    condition_target target_;
};

} // namespace ddwaf
