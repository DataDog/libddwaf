// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "transformer/base.hpp"

namespace ddwaf::transformer {

class unicode_normalize : public base<unicode_normalize> {
public:
    static transformer_id id() { return transformer_id::unicode_normalize; }
    static std::string_view name() { return "unicode_normalize"; }

protected:
    static bool needs_transform(std::string_view str);
    static bool transform_impl(lazy_string &str);

    friend class base<unicode_normalize>;
};

} // namespace ddwaf::transformer
