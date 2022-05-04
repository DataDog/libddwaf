// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <filesystem>
#include <string_view>
#include <unordered_set>

namespace fs = std::filesystem;

namespace ddwaf::benchmark {

enum class output_fmt { none, human, csv, json };

struct settings {
    fs::path rule_repo;
    std::unordered_set<std::string_view> test_list;
    output_fmt format;
    fs::path output_file;
    unsigned iterations{100};
    unsigned long seed{20};
    unsigned threads{0};
    unsigned max_objects{100};
};

} // namespace ddwaf::benchmark
