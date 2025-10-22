// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <string_view>

namespace ddwaf {

class base_checksum {
public:
    base_checksum() = default;
    base_checksum(const base_checksum &) = default;
    base_checksum &operator=(const base_checksum &) = default;
    base_checksum(base_checksum &&) = default;
    base_checksum &operator=(base_checksum &&) = default;
    virtual ~base_checksum() = default;

    [[nodiscard]] virtual bool validate(std::string_view str) const noexcept = 0;
};

} // namespace ddwaf
