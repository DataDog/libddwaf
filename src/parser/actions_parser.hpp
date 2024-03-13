// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>

#include "action_mapper.hpp"
#include "parameter.hpp"
#include "ruleset_info.hpp"

using base_section_info = ddwaf::base_ruleset_info::base_section_info;

namespace ddwaf::parser::v2 {

std::shared_ptr<action_mapper> parse_actions(
    parameter::vector &actions_array, base_section_info &info);

} // namespace ddwaf::parser::v2
