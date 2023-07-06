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

#include <generator/base.hpp>
#include <utils.hpp>

namespace ddwaf::generator {

class extract_schema : public base {
public:
    extract_schema() = default;
    ~extract_schema() override = default;
    extract_schema(const extract_schema &) = default;
    extract_schema(extract_schema &&) = default;
    extract_schema &operator=(const extract_schema &) = default;
    extract_schema &operator=(extract_schema &&) = default;

    ddwaf_object generate(const ddwaf_object *input) override;
};

} // namespace ddwaf::generator