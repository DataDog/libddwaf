// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <string_view>

#include "checksum/base.hpp"

namespace ddwaf {

class luhn_checksum : public base_checksum {
public:
    luhn_checksum() = default;
    luhn_checksum(const luhn_checksum &) = default;
    luhn_checksum &operator=(const luhn_checksum &) = default;
    luhn_checksum(luhn_checksum &&) = default;
    luhn_checksum &operator=(luhn_checksum &&) = default;
    ~luhn_checksum() override = default;

    [[nodiscard]] bool validate(std::string_view str) const noexcept override;
};

} // namespace ddwaf
