// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <concepts>

#include "builder/processor_builder.hpp"
#include "processor/extract_schema.hpp"

namespace ddwaf {

namespace {
std::set<const scanner *> references_to_scanners(
    const std::vector<parser::reference_spec> &references, const indexer<const scanner> &scanners)
{
    std::set<const scanner *> scanner_refs;
    for (const auto &ref : references) {
        if (ref.type == parser::reference_type::id) {
            const auto *scanner = scanners.find_by_id(ref.ref_id);
            if (scanner == nullptr) {
                continue;
            }
            scanner_refs.emplace(scanner);
        } else if (ref.type == parser::reference_type::tags) {
            auto current_refs = scanners.find_by_tags(ref.tags);
            scanner_refs.merge(current_refs);
        }
    }
    return scanner_refs;
}

template <typename T> struct typed_processor_builder;

template <> struct typed_processor_builder<extract_schema> {
    std::shared_ptr<base_processor> build(const auto &spec, const auto &scanners)
    {
        auto ref_scanners = references_to_scanners(spec.scanners, scanners);
        return std::make_shared<extract_schema>(
            spec.id, spec.expr, spec.mappings, std::move(ref_scanners), spec.evaluate, spec.output);
    }
};

template <typename T, typename Spec, typename Scanners>
concept has_build_with_scanners =
    requires(typed_processor_builder<T> b, Spec spec, Scanners scanners) {
        {
            b.build(spec, scanners)
        } -> std::same_as<std::shared_ptr<base_processor>>;
    };

template <typename T>
[[nodiscard]] std::shared_ptr<base_processor> build_with_type(
    const auto &spec, const auto &scanners)
    requires std::is_base_of_v<base_processor, T>
{
    typed_processor_builder<T> typed_builder;
    if constexpr (has_build_with_scanners<T, decltype(spec), decltype(scanners)>) {
        return typed_builder.build(spec, scanners);
    } else {
        return typed_builder.build(spec);
    }
}
} // namespace

[[nodiscard]] std::shared_ptr<base_processor> processor_builder::build(
    const indexer<const scanner> &scanners) const
{
    switch (type) {
    case processor_type::extract_schema:
        return build_with_type<extract_schema>(*this, scanners);
    default:
        break;
    }
    return {};
}
} // namespace ddwaf
