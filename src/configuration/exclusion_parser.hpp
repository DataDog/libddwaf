// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "configuration/common/configuration_collector.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "ruleset_info.hpp"

namespace ddwaf {

void parse_filters(const raw_configuration::vector &filter_array, configuration_collector &cfg,
    ruleset_info::base_section_info &info);

} // namespace ddwaf
