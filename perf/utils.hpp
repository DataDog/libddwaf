// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#pragma once

#include <ddwaf.h>

namespace ddwaf::benchmark::utils
{

std::string object_to_string(const ddwaf_object &o) noexcept;

}
