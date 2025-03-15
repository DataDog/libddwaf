// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/structured_condition.hpp"

namespace ddwaf {

class lfi_detector : public base_impl<lfi_detector> {
public:
    static constexpr unsigned version = 2;
    static constexpr std::array<std::string_view, 2> param_names{"resource", "params"};

    explicit lfi_detector(std::vector<condition_parameter> args)
        : base_impl<lfi_detector>(std::move(args))
    {}

protected:
    [[nodiscard]] eval_result eval_impl(const unary_argument<std::string_view> &path,
        const variadic_argument<object_view> &params, condition_cache &cache,
        const exclusion::object_set_ref &objects_excluded, const object_limits &limits,
        ddwaf::timer &deadline) const;

    friend class base_impl<lfi_detector>;
};

} // namespace ddwaf
