// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <transformer/base.hpp>

namespace ddwaf::transformer {

class normalize_path : public base<normalize_path> {
public:
    static transformer_id id() { return transformer_id::normalize_path; }
    static std::string_view name() { return "normalize_path"; }

    static bool transform_impl(lazy_string &str);
};

} // namespace ddwaf::transformer
