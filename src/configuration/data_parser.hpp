// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "parameter.hpp"

namespace ddwaf {

bool parse_rule_data(const parameter::vector &data_array, configuration_spec &cfg, base_section_info &info);
bool parse_exclusion_data(const parameter::vector &data_array, configuration_spec &cfg, base_section_info &info);

} // namespace ddwaf
