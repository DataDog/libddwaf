// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "processor/fingerprint.hpp"
#include "sha256.hpp"
#include "transformer/lowercase.hpp"

namespace ddwaf {
namespace fingerprint {

// Retur true if the first argument is less than (i.e. is ordered before) the second
bool str_casei_cmp(std::string_view left, std::string_view right)
{
    auto n = std::min(left.size(), right.size());
    for (std::size_t i = 0; i < n; ++i) {
        auto lc = ddwaf::tolower(left[i]);
        auto rc = ddwaf::tolower(right[i]);
        if (lc != rc) {
            return lc < rc;
        }
    }
    return left.size() <= right.size();
}

void normalize_string(std::string_view key, std::string &buffer, bool trailing_separator)
{
    // Clear should not deallocate...
    // TODO: verify
    buffer.clear();

    if (buffer.capacity() < key.size()) {
        // Add space for the extra comma, just in case
        buffer.reserve(key.size() + 1);
    }

    for (auto c : key) {
        if (c == ',') {
            buffer.append(R"(\,)");
        } else {
            buffer.append(1, ddwaf::tolower(c));
        }
    }

    if (trailing_separator) {
        buffer.append(1, ',');
    }
}

void string_hash_field::operator()(string_buffer &output)
{
    cow_string value_lc{value};
    transformer::lowercase::transform(value_lc);

    sha256_hash hasher;
    hasher << static_cast<std::string_view>(value_lc);

    hasher.write_digest(output.subspan<8>());
}

void key_hash_field::operator()(string_buffer &output)
{
    if (value.type != DDWAF_OBJ_MAP or value.nbEntries == 0) {
        return;
    }

    std::vector<std::string_view> keys;
    keys.reserve(value.nbEntries);

    for (unsigned i = 0; i < value.nbEntries; ++i) {
        const auto &child = value.array[i];

        std::string_view key{
            child.parameterName, static_cast<std::size_t>(child.parameterNameLength)};

        keys.emplace_back(key);
    }

    std::sort(keys.begin(), keys.end(), str_casei_cmp);

    sha256_hash hasher;
    std::string normalized;
    for (unsigned i = 0; i < keys.size(); ++i) {
        normalize_string(keys[i], normalized, (i + 1) < keys.size());
        hasher << normalized;
    }

    hasher.write_digest(output.subspan<8>());
}

} // namespace fingerprint

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::pair<ddwaf_object, object_store::attribute> http_fingerprint::eval_impl(
    const unary_argument<std::string_view> &method, const unary_argument<std::string_view> &uri_raw,
    const unary_argument<const ddwaf_object *> &body,
    const unary_argument<const ddwaf_object *> &query, ddwaf::timer &deadline) const
{
    if (deadline.expired()) {
        throw ddwaf::timeout_exception();
    }

    auto res = fingerprint::generate_fragment("http", fingerprint::string_field{method.value},
        fingerprint::string_hash_field{uri_raw.value}, fingerprint::key_hash_field{*body.value},
        fingerprint::key_hash_field{*query.value});

    return {res, object_store::attribute::none};
}

} // namespace ddwaf
