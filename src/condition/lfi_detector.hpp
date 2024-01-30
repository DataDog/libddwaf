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
    using param_names = param_names_spec<"resource"_cs, "params"_cs>;

    explicit lfi_detector(std::vector<argument_definition> args)
        : base_impl<lfi_detector>(std::move(args))
    {}

protected:
    eval_result eval_impl(argument<std::string_view> path,
        variadic_argument<const ddwaf_object *> params, std::reference_wrapper<cache_type> cache,
        std::reference_wrapper<timer> deadline) const;

    friend class base_impl<lfi_detector>;
};

} // namespace ddwaf::condition
