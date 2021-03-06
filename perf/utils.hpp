// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <filesystem>

namespace fs = std::filesystem;

namespace ddwaf::benchmark::utils {

std::string object_to_string(const ddwaf_object &o) noexcept;
ddwaf_object object_dup(const ddwaf_object &o) noexcept;
std::string read_file(const fs::path &filename);

} // namespace ddwaf::benchmark::utils
