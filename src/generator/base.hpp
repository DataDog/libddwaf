// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <utils.hpp>

namespace ddwaf::generator {

class base {
public:
    using ptr = std::unique_ptr<base>;

    base() = default;
    virtual ~base() = default;
    base(const base &) = default;
    base(base &&) = default;
    base &operator=(const base &) = default;
    base &operator=(base &&) = default;

    virtual ddwaf_object generate(const ddwaf_object *input) = 0;
};

} // namespace ddwaf::generator
