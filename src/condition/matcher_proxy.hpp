// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/base.hpp"

namespace ddwaf::condition {

class matcher_proxy : public base_impl<matcher_proxy> {
public:
    matcher_proxy(std::unique_ptr<matcher::base> &&matcher, std::string data_id,
        std::vector<argument_definition> args)
        : base_impl<matcher_proxy>(std::move(args)), matcher_(std::move(matcher)),
          data_id_(std::move(data_id))
    {}

protected:
    eval_result eval_impl(const argument_stack &stack, cache_type &cache,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        const object_limits &limits, ddwaf::timer &deadline) const;

    [[nodiscard]] const matcher::base *get_matcher(
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers)
        const;

    static const std::vector<argument_specification> &arguments_impl()
    {
        static std::vector<argument_specification> args = {
            {"inputs", object_type::any, true, false}};
        return args;
    };

    std::unique_ptr<matcher::base> matcher_;
    std::string data_id_;

    friend class base_impl<matcher_proxy>;
};

} // namespace ddwaf::condition
