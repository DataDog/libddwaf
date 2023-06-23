// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <transformer/base.hpp>

namespace ddwaf::transformer {

class url_decode : public base<url_decode> {
public:
    static transformer_id id() { return transformer_id::url_decode; }
    static std::string_view name() { return "url_decode"; }

protected:
    static bool needs_transform(std::string_view /*str*/) { return true; }
    static bool transform_impl(lazy_string &str);

    friend class base<url_decode>;
};

} // namespace ddwaf::transformer
