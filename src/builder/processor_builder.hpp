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
#include "processor/base.hpp"

namespace ddwaf {

enum class processor_type : unsigned {
    extract_schema,
    http_endpoint_fingerprint,
    http_network_fingerprint,
    http_header_fingerprint,
    session_fingerprint,
    copy_data,
};

struct processor_builder {
    [[nodiscard]] std::shared_ptr<base_processor> build(
        const indexer<const scanner> &scanners) const;

    processor_type type;
    std::string id;
    std::shared_ptr<expression> expr;
    std::vector<processor_mapping> mappings;
    std::vector<parser::reference_spec> scanners;
    bool evaluate{false};
    bool output{true};
};

struct processor_container {
    [[nodiscard]] bool empty() const { return pre.empty() && post.empty(); }
    [[nodiscard]] std::size_t size() const { return pre.size() + post.size(); }
    void clear()
    {
        pre.clear();
        post.clear();
    }

    std::vector<processor_builder> pre;
    std::vector<processor_builder> post;
};

} // namespace ddwaf
