// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "indexer.hpp"
#include "parser/specification.hpp"
#include "processor.hpp"

namespace ddwaf {

enum class processor_type : unsigned {
    extract_schema,
    // Reserved
    http_fingerprint,
    session_fingerprint,
    network_fingerprint,
    header_fingerprint,
};

struct processor_builder {
    [[nodiscard]] std::shared_ptr<base_processor> build(
        const indexer<const scanner> &scanners) const;

    processor_type type;
    std::string id;
    std::shared_ptr<expression> expr;
    std::vector<processor::target_mapping> mappings;
    std::vector<parser::reference_spec> scanners;
    bool evaluate{false};
    bool output{true};
};

} // namespace ddwaf
