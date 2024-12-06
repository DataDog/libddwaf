// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "configuration/common.hpp"
#include "configuration/configuration.hpp"
#include "parameter.hpp"
#include "processor/base.hpp"
#include "ruleset_info.hpp"

namespace ddwaf {

processor_container parse_processors(parameter::vector &processor_array, base_section_info &info,
    const object_limits &limits, spec_id_tracker &ids);

} // namespace ddwaf
