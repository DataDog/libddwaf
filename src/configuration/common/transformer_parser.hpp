// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "condition/base.hpp"
#include "configuration/common/raw_configuration.hpp"
#include "transformer/base.hpp"

namespace ddwaf {

std::vector<transformer_id> parse_transformers(
    const raw_configuration::vector &root, data_source &source);

std::optional<transformer_id> transformer_from_string(std::string_view str);

} // namespace ddwaf
