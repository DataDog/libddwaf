// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "transformer/base.hpp"

namespace ddwaf::transformer {

class remove_comments : public base<remove_comments> {
public:
    static transformer_id id() { return transformer_id::remove_comments; }
    static std::string_view name() { return "remove_comments"; }

protected:
    static bool needs_transform(std::string_view /*str*/) { return true; }
    static bool transform_impl(lazy_string &str);

    friend class base<remove_comments>;
};

} // namespace ddwaf::transformer
