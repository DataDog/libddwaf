// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "cow_string.hpp"
#include "transformer/base.hpp"
#include <string_view>

namespace ddwaf::transformer {

class remove_nulls : public base<remove_nulls> {
public:
    static transformer_id id() { return transformer_id::remove_nulls; }
    static std::string_view name() { return "remove_nulls"; }

protected:
    static bool needs_transform(std::string_view /*str*/) { return true; }
    static bool transform_impl(cow_string &str);

    friend class base<remove_nulls>;
};

} // namespace ddwaf::transformer
