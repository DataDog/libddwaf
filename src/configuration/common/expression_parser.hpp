// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "configuration/common/common.hpp"
#include "expression.hpp"
#include "configuration/common/raw_configuration.hpp"

namespace ddwaf {

// TODO: merge these and use default arguments
std::shared_ptr<expression> parse_expression(const raw_configuration::vector &conditions_array,
    data_source source, const std::vector<transformer_id> &transformers,
    address_container &addresses, const object_limits &limits);

std::shared_ptr<expression> parse_simplified_expression(
    const raw_configuration::vector &conditions_array, address_container &addresses,
    const object_limits &limits);

} // namespace ddwaf
