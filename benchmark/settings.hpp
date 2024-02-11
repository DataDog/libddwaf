// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <filesystem>
#include <regex>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace fs = std::filesystem;

namespace ddwaf::benchmark {

enum class output_fmt { none, human, csv, json };

struct settings {
    std::vector<fs::path> scenarios;
    output_fmt format{output_fmt::json};
    fs::path output_file;
    unsigned runs{1};
    unsigned iterations{1000};
    unsigned warmup_iterations{10};
    unsigned seed{1729};
    std::regex fixtures{".*"};
};

} // namespace ddwaf::benchmark
