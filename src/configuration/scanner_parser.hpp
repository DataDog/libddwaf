// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "configuration/configuration.hpp"
#include "indexer.hpp"
#include "parameter.hpp"
#include "ruleset_info.hpp"
#include "scanner.hpp"

namespace ddwaf {

scanner_container parse_scanners(
    parameter::vector &scanner_array, ruleset_info::base_section_info &info, spec_id_tracker &ids);

} // namespace ddwaf
