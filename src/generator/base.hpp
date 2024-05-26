// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <vector>

#include "clock.hpp"
#include "object_view.hpp"
#include "scanner.hpp"
#include "utils.hpp"

namespace ddwaf::generator {

class base {
public:
    base() = default;
    virtual ~base() = default;
    base(const base &) = default;
    base(base &&) = default;
    base &operator=(const base &) = default;
    base &operator=(base &&) = default;

    virtual owned_object generate(
        object_view input, const std::set<const scanner *> &scanners, ddwaf::timer &deadline) = 0;
};

} // namespace ddwaf::generator
