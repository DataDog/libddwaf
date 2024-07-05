// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.


#include "sha256.hpp"
#include "processor/fingerprint_common.hpp"
#include "processor/http_fingerprint.hpp"
#include "transformer/lowercase.hpp"

namespace ddwaf {

std::pair<ddwaf_object, object_store::attribute> http_fingerprint::eval_impl(
    const unary_argument<std::string_view> &method, const unary_argument<std::string_view> &uri_raw,
    const unary_argument<const ddwaf_object *> &body,
    const unary_argument<const ddwaf_object *> &query, ddwaf::timer &deadline) const
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    auto res = fingerprint::generate_fragment("http",
        fingerprint::string_field{method.value},
        fingerprint::string_hash_field{uri_raw.value},
        fingerprint::key_hash_field{*body.value},
        fingerprint::key_hash_field{*query.value});

    return {res, object_store::attribute::none};
}

} // namespace ddwaf
