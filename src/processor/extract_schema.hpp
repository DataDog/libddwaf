// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <set>

#include "processor/base.hpp"
#include "scanner.hpp"

namespace ddwaf {

class extract_schema : public structured_processor<extract_schema> {
public:
    static constexpr std::size_t max_container_depth = 18;
    static constexpr std::size_t max_array_nodes = 10;
    static constexpr std::size_t max_record_nodes = 255;

    extract_schema(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, std::set<const scanner *> scanners, bool evaluate,
        bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output),
          scanners_(std::move(scanners))
    {}

    ddwaf_object eval_impl(const ddwaf_object *input, ddwaf::timer &deadline) const;

protected:
    std::set<const scanner *> scanners_;
};

} // namespace ddwaf
