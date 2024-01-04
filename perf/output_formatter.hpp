// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <map>
#include <string>
#include <string_view>

#include "runner.hpp"
#include "settings.hpp"

namespace ddwaf::benchmark {

void output_results(
    const benchmark::settings &s, const std::map<std::string, runner::test_result> &results);

} // namespace ddwaf::benchmark
