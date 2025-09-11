// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>

#include "checksum/base.hpp"

namespace ddwaf {

struct checksum_builder {
    static std::unique_ptr<base_checksum> build(std::string_view name);
};

} // namespace ddwaf
