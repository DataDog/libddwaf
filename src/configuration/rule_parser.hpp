// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "configuration/common/common.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/raw_configuration.hpp"

namespace ddwaf {

void parse_base_rules(const raw_configuration::vector &rule_array, configuration_collector &cfg,
    base_section_info &info, const object_limits &limits);

void parse_user_rules(const raw_configuration::vector &rule_array, configuration_collector &cfg,
    base_section_info &info, const object_limits &limits);

} // namespace ddwaf
