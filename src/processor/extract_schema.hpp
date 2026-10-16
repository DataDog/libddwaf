// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <array>
#include <cstddef>
#include <memory>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "expression.hpp"
#include "memory_resource.hpp"
#include "object.hpp"
#include "pointer.hpp"
#include "processor/base.hpp"
#include "scanner.hpp"

namespace ddwaf {

class extract_schema : public structured_processor<extract_schema> {
public:
    static constexpr std::array<std::string_view, 1> param_names{"inputs"};

    static constexpr std::size_t max_container_depth = 18;
    static constexpr std::size_t max_array_nodes = 10;
    static constexpr std::size_t max_record_nodes = 255;

    // A scanner along with a copy of its tags. Schema nodes refer to the copy
    // instead of copying the tags on every match; since the copy is made
    // the same way, it is iterated (and therefore serialised) in the same
    // order as a per-node copy would be.
    struct scanner_entry {
        const scanner *instance;
        std::unordered_map<std::string, std::string> tags;
    };

    extract_schema(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, const std::set<const scanner *> &scanners,
        bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {
        scanners_.reserve(scanners.size());
        for (const auto *scnr : scanners) {
            scanners_.push_back({.instance = scnr, .tags = scnr->get_tags()});
        }
    }

    owned_object eval_impl(const unary_argument<object_view> &input, processor_cache &cache,
        nonnull_ptr<memory::memory_resource> alloc, ddwaf::timer &deadline) const;

protected:
    // In the iteration order of the original set
    std::vector<scanner_entry> scanners_;
};

} // namespace ddwaf
