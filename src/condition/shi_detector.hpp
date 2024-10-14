// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/structured_condition.hpp"
#include "matcher/ip_match.hpp"

namespace ddwaf {

class shi_detector : public base_impl<shi_detector> {
public:
    static constexpr unsigned version = 1;
    static constexpr std::array<std::string_view, 2> param_names{"resource", "params"};

    explicit shi_detector(std::vector<condition_parameter> args, const object_limits &limits = {});

protected:
    // TODO support array shell_args
    [[nodiscard]] eval_result eval_impl(const unary_argument<std::string_view> &resource,
        const variadic_argument<const ddwaf_object *> &params, condition_cache &cache,
        const exclusion::object_set_ref &objects_excluded, ddwaf::timer &deadline) const;

    friend class base_impl<shi_detector>;
};

} // namespace ddwaf
