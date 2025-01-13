// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "configuration/common/common.hpp"
#include "configuration/common/configuration.hpp"
#include "configuration/common/configuration_collector.hpp"
#include "parameter.hpp"

namespace ddwaf {

bool parse_legacy_rules(const parameter::vector &rule_array, configuration_collector &cfg,
    base_section_info &info, object_limits limits);

} // namespace ddwaf
