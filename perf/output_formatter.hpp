// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#pragma once

#include <map>
#include <string>
#include <string_view>

#include "runner.hpp"

namespace ddwaf::benchmark
{

using output_fn_type = 
    void (*)(const std::map<std::string_view, runner::test_result> &results);

void output_csv(const std::map<std::string_view, runner::test_result> &results);
void output_json(const std::map<std::string_view, runner::test_result> &results);
void output_human(const std::map<std::string_view, runner::test_result> &results);

}
