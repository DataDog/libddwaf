// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "configuration/common/configuration.hpp"
#include "parameter.hpp"
#include "ruleset_info.hpp"

namespace ddwaf {

bool parse_filters(const parameter::vector &filter_array, configuration_spec &cfg,
    spec_id_tracker &ids, ruleset_info::base_section_info &info, const object_limits &limits);

} // namespace ddwaf
