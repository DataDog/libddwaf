// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <string>
#include <unordered_map>

#include "configuration/configuration.hpp"
#include "parameter.hpp"
#include "ruleset_info.hpp"

namespace ddwaf {

filter_spec_container parse_filters(parameter::vector &filter_array,
    ruleset_info::base_section_info &info, const object_limits &limits, spec_id_tracker &ids);

} // namespace ddwaf
