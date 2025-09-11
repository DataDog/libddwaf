// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <cstdlib>
#include <cstring>
#include <string_view>

#include "checksum/base.hpp"

namespace ddwaf {

class luhn_checksum : public base_checksum_impl<luhn_checksum> {
protected:
    static bool validate_impl(std::string_view str) noexcept;
    friend class base_checksum_impl<luhn_checksum>;
};

} // namespace ddwaf
