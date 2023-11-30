// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/base.hpp"

namespace ddwaf::condition {

class lfi_detector : public base_impl<lfi_detector> {
public:
    explicit lfi_detector(std::vector<argument_definition> args)
        : base_impl<lfi_detector>(std::move(args))
    {}

protected:
    static eval_result eval_impl(const argument_stack &stack, cache_type &cache,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        const object_limits &limits, ddwaf::timer &deadline);

    static constexpr std::vector<argument_specification> arguments()
    {
        return {{"path", object_type::string, false, false},
            {"params", object_type::container, true, false}};
    };

    friend class base_impl<lfi_detector>;
};

} // namespace ddwaf::condition
