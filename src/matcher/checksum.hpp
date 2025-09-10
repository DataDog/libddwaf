// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <cstdint>
#include <string_view>

namespace ddwaf {

enum class checksum_algorithm : uint8_t { none, luhn };

checksum_algorithm checksum_algorithm_from_string(std::string_view str);
bool checksum_eval(checksum_algorithm algo, std::string_view str);

} // namespace ddwaf
