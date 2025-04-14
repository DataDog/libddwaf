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

class processor_builder {
public:
    processor_builder(std::string id, processor_spec spec)
        : id_(std::move(id)), spec_(std::move(spec))
    {}

    std::unique_ptr<base_processor> build(const indexer<const scanner> &scanners);

    bool apply_override(const processor_override_spec &ovrd)
    {
        // TODO error if processor doesn't support scanners
        spec_.scanners = ovrd.scanners;
        return true;
    }

protected:
    std::string id_;
    processor_spec spec_;
};

} // namespace ddwaf
