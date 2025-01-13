// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "configuration/common/configuration.hpp"

namespace ddwaf {

struct matcher_builder {
    static std::shared_ptr<matcher::base> build(const data_spec &data);
};

} // namespace ddwaf
