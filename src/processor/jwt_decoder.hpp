// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include "processor/base.hpp"

namespace ddwaf {

class jwt_decoder : public structured_processor<jwt_decoder> {
public:
    static constexpr std::array<std::string_view, 1> param_names{"inputs"};

    jwt_decoder(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {}

    std::pair<ddwaf_object, object_store::attribute> eval_impl(
        const unary_argument<const ddwaf_object *> &input, processor_cache &cache,
        ddwaf::timer &deadline) const;
};

} // namespace ddwaf
