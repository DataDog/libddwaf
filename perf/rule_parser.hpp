// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <filesystem>

namespace fs = std::filesystem;

namespace ddwaf::benchmark::rule_parser {

ddwaf_object from_file(fs::path &filename);

}
