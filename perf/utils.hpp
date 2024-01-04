// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <charconv>
#include <ddwaf.h>
#include <filesystem>

namespace fs = std::filesystem;

namespace ddwaf::benchmark::utils {

std::string object_to_string(const ddwaf_object &o) noexcept;
ddwaf_object object_dup(const ddwaf_object &o) noexcept;
std::string read_file(const fs::path &filename);

inline void exit_failure()
{
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    exit(EXIT_FAILURE);
}

inline void exit_success()
{
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    exit(EXIT_SUCCESS);
}

template <typename T> T from_string(std::string_view str)
{
    T result;
    const auto *end = str.data() + str.size();
    auto [endConv, err] = std::from_chars(str.data(), end, result);
    if (err == std::errc{} && endConv == end) {
        return result;
    }
    return T();
}

} // namespace ddwaf::benchmark::utils
