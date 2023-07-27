// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "transformer/base.hpp"

namespace ddwaf::transformer {

class css_decode : public base<css_decode> {
public:
    static transformer_id id() { return transformer_id::css_decode; }
    static std::string_view name() { return "css_decode"; }

protected:
    static bool needs_transform(std::string_view /*str*/) { return true; }
    static bool transform_impl(cow_string &str);

    friend class base<css_decode>;
};

} // namespace ddwaf::transformer
