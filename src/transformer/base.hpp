// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdlib>
#include <cstring>
#include <ddwaf.h>
#include <string_view>

#include <lazy_string.hpp>

namespace ddwaf {

enum class transformer_id : uint8_t {
    invalid = 0,
    lowercase,
    remove_nulls,
};

namespace transformer {

template <typename Derived>
class base {
public:
    bool transform(lazy_string &str) {
        return static_cast<Derived*>(this)->transform_impl(str);
    }
};

} // namespace transformer
} // namespace ddwaf
