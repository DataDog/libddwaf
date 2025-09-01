// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include "processor/base.hpp"

namespace ddwaf {

class uri_parse_processor : public structured_processor<uri_parse_processor> {
public:
    static constexpr std::array<std::string_view, 1> param_names{"inputs"};

    uri_parse_processor(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {}

    std::pair<owned_object, object_store::attribute> eval_impl(
        const unary_argument<std::string_view> &input, processor_cache &cache,
        nonnull_ptr<memory::memory_resource> alloc, ddwaf::timer &deadline) const;
};

} // namespace ddwaf
