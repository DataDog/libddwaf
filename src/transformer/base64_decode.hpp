// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "transformer/base.hpp"

namespace ddwaf::transformer {

class base64_decode : public base<base64_decode> {
public:
    static transformer_id id() { return transformer_id::base64_decode; }
    static std::string_view name() { return "base64_decode"; }

protected:
    static bool needs_transform(std::string_view str);
    static bool transform_impl(cow_string &str);

    friend class base<base64_decode>;
};

class base64url_decode : public base<base64url_decode> {
public:
    static transformer_id id() { return transformer_id::base64url_decode; }
    static std::string_view name() { return "base64url_decode"; }

protected:
    static bool needs_transform(std::string_view str);
    static bool transform_impl(cow_string &str);

    friend class base<base64url_decode>;
};

} // namespace ddwaf::transformer
