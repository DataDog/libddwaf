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
        if (spec_.type != processor_type::extract_schema) {
            return false;
        }

        auto &[include, exclude] = spec_.scanners;
        include.insert(include.end(), ovrd.scanners.include.begin(), ovrd.scanners.include.end());
        exclude.insert(exclude.end(), ovrd.scanners.exclude.begin(), ovrd.scanners.exclude.end());

        return true;
    }

    [[nodiscard]] std::string_view get_id() const { return id_; }

protected:
    std::string id_;
    processor_spec spec_;
};

} // namespace ddwaf
