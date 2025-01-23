// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "configuration/common/configuration.hpp"
#include "parameter.hpp"

namespace ddwaf {

reference_spec parse_reference(const parameter::map &target);

} // namespace ddwaf
