// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/base.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "expression.hpp"
#include "transformer/base.hpp"
#include <memory>
#include <vector>

namespace ddwaf {

// TODO: merge these and use default arguments
std::shared_ptr<expression> parse_expression(const raw_configuration::vector &conditions_array,
    data_source source, const std::vector<transformer_id> &transformers);

std::shared_ptr<expression> parse_simplified_expression(
    const raw_configuration::vector &conditions_array);

} // namespace ddwaf
