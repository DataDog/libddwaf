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

class normalize_path_win : public base<normalize_path_win> {
public:
    static transformer_id id() { return transformer_id::normalize_path_win; }
    static std::string_view name() { return "normalize_path_win"; }

protected:
    static bool needs_transform(std::string_view /*str*/) { return true; }
    static bool transform_impl(cow_string &str);

    friend class base<normalize_path_win>;
};

class normalize_path : public base<normalize_path> {
public:
    static transformer_id id() { return transformer_id::normalize_path; }
    static std::string_view name() { return "normalize_path"; }

protected:
    static bool needs_transform(std::string_view /*str*/) { return true; }
    static bool transform_impl(cow_string &str);

    friend class base<normalize_path>;
    friend class normalize_path_win;
};

} // namespace ddwaf::transformer
