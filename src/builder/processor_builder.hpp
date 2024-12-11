// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>

#include "configuration/common/configuration.hpp"
#include "indexer.hpp"
#include "processor/base.hpp"

namespace ddwaf {

struct processor_builder {
    static std::shared_ptr<base_processor> build(
        const processor_spec &spec, const indexer<const scanner> &scanners);
};

} // namespace ddwaf
