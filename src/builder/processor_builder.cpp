// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "builder/processor_builder.hpp"
#include "configuration/common/configuration.hpp"
#include "indexer.hpp"
#include "processor/base.hpp"
#include "processor/extract_schema.hpp"
#include "processor/fingerprint.hpp"
#include "processor/jwt_decode.hpp"
#include "scanner.hpp"

namespace ddwaf {

namespace {
std::set<const scanner *> references_to_scanners(
    const std::vector<reference_spec> &references, const indexer<const scanner> &scanners)
{
    std::set<const scanner *> scanner_refs;
    for (const auto &ref : references) {
        if (ref.type == reference_type::id) {
            const auto *scanner = scanners.find_by_id(ref.ref_id);
            if (scanner == nullptr) {
                continue;
            }
            scanner_refs.emplace(scanner);
        } else if (ref.type == reference_type::tags) {
            auto current_refs = scanners.find_by_tags(ref.tags);
            scanner_refs.merge(current_refs);
        }
    }
    return scanner_refs;
}

template <typename T> struct typed_processor_builder;

template <> struct typed_processor_builder<extract_schema> {
    static std::unique_ptr<base_processor> build(
        const std::string &id, const processor_spec &spec, const indexer<const scanner> &scanners)
    {
        auto ref_scanners = references_to_scanners(spec.scanners, scanners);
        return std::make_unique<extract_schema>(
            id, spec.expr, spec.mappings, std::move(ref_scanners), spec.evaluate, spec.output);
    }
};

template <> struct typed_processor_builder<http_endpoint_fingerprint> {
    static std::unique_ptr<base_processor> build(const std::string &id, const processor_spec &spec)
    {
        return std::make_unique<http_endpoint_fingerprint>(
            id, spec.expr, spec.mappings, spec.evaluate, spec.output);
    }
};

template <> struct typed_processor_builder<http_header_fingerprint> {
    static std::unique_ptr<base_processor> build(const std::string &id, const processor_spec &spec)
    {
        return std::make_unique<http_header_fingerprint>(
            id, spec.expr, spec.mappings, spec.evaluate, spec.output);
    }
};

template <> struct typed_processor_builder<http_network_fingerprint> {
    static std::unique_ptr<base_processor> build(const std::string &id, const processor_spec &spec)
    {
        return std::make_unique<http_network_fingerprint>(
            id, spec.expr, spec.mappings, spec.evaluate, spec.output);
    }
};

template <> struct typed_processor_builder<session_fingerprint> {
    static std::unique_ptr<base_processor> build(const std::string &id, const processor_spec &spec)
    {
        return std::make_unique<session_fingerprint>(
            id, spec.expr, spec.mappings, spec.evaluate, spec.output);
    }
};

template <> struct typed_processor_builder<jwt_decode> {
    static std::unique_ptr<base_processor> build(const std::string &id, const processor_spec &spec)
    {
        return std::make_unique<jwt_decode>(
            id, spec.expr, spec.mappings, spec.evaluate, spec.output);
    }
};

template <typename T, typename Id, typename Spec, typename Scanners>
concept has_build_with_scanners =
    requires(typed_processor_builder<T> b, Id id, Spec spec, Scanners scanners) {
        {
            b.build(id, spec, scanners)
        } -> std::same_as<std::unique_ptr<base_processor>>;
    };

template <typename T>
[[nodiscard]] std::unique_ptr<base_processor> build_with_type(
    const std::string &id, const processor_spec &spec, const indexer<const scanner> &scanners)
    requires std::is_base_of_v<base_processor, T>
{
    if constexpr (has_build_with_scanners<T, decltype(id), decltype(spec), decltype(scanners)>) {
        return typed_processor_builder<T>::build(id, spec, scanners);
    } else {
        return typed_processor_builder<T>::build(id, spec);
    }
}
} // namespace

// NOLINTNEXTLINE(readability-convert-member-functions-to-static)
std::unique_ptr<base_processor> processor_builder::build(const indexer<const scanner> &scanners)
{
    switch (spec_.type) {
    case processor_type::extract_schema:
        return build_with_type<extract_schema>(id_, spec_, scanners);
    case processor_type::http_endpoint_fingerprint:
        return build_with_type<http_endpoint_fingerprint>(id_, spec_, scanners);
    case processor_type::http_header_fingerprint:
        return build_with_type<http_header_fingerprint>(id_, spec_, scanners);
    case processor_type::http_network_fingerprint:
        return build_with_type<http_network_fingerprint>(id_, spec_, scanners);
    case processor_type::session_fingerprint:
        return build_with_type<session_fingerprint>(id_, spec_, scanners);
    case processor_type::jwt_decode:
        return build_with_type<jwt_decode>(id_, spec_, scanners);
    default:
        break;
    }
    return {};
}
} // namespace ddwaf
