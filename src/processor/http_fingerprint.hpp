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

class http_fingerprint : public structured_processor<http_fingerprint> {
public:
    static constexpr std::array<std::string_view, 4> param_names{
        "method", "uri_raw", "query", "body"};

    http_fingerprint(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {}

    std::pair<ddwaf_object, object_store::attribute> eval_impl(
        const unary_argument<std::string_view> &method,
        const unary_argument<std::string_view> &uri_raw,
        const unary_argument<const ddwaf_object *> &query,
        const unary_argument<const ddwaf_object *> &body, ddwaf::timer &deadline) const;
};

} // namespace ddwaf
