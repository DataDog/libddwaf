// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdlib>
#include <cstring>
#include <string_view>

#include "processor/base.hpp"

namespace ddwaf {

class http_endpoint_fingerprint : public structured_processor<http_endpoint_fingerprint> {
public:
    static constexpr std::array<std::string_view, 4> param_names{
        "method", "uri_raw", "query", "body"};

    http_endpoint_fingerprint(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {}

    std::pair<owned_object, object_store::attribute> eval_impl(
        const unary_argument<std::string_view> &method,
        const unary_argument<std::string_view> &uri_raw,
        const optional_argument<object_view> &query, const optional_argument<object_view> &body,
        processor_cache &cache, ddwaf::timer &deadline) const;
};

class http_header_fingerprint : public structured_processor<http_header_fingerprint> {
public:
    static constexpr std::array<std::string_view, 1> param_names{"headers"};

    http_header_fingerprint(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {}

    std::pair<owned_object, object_store::attribute> eval_impl(
        const unary_argument<object_view> &headers, processor_cache &cache,
        ddwaf::timer &deadline) const;
};

class http_network_fingerprint : public structured_processor<http_network_fingerprint> {
public:
    static constexpr std::array<std::string_view, 1> param_names{"headers"};

    http_network_fingerprint(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {}

    std::pair<owned_object, object_store::attribute> eval_impl(
        const unary_argument<object_view> &headers, processor_cache &cache,
        ddwaf::timer &deadline) const;
};

class session_fingerprint : public structured_processor<session_fingerprint> {
public:
    static constexpr std::array<std::string_view, 3> param_names{
        "cookies", "session_id", "user_id"};

    session_fingerprint(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {}

    std::pair<owned_object, object_store::attribute> eval_impl(
        const optional_argument<object_view> &cookies,
        const optional_argument<std::string_view> &session_id,
        const optional_argument<std::string_view> &user_id, processor_cache &cache,
        ddwaf::timer &deadline) const;
};

} // namespace ddwaf
