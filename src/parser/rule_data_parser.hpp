// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <parameter.hpp>
#include <parser/common.hpp>
#include <string_view>

namespace ddwaf::parser {

template <typename T> T parse_rule_data(std::string_view type, parameter &input);

}
