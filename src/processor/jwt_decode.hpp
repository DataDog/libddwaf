// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include "argument_retriever.hpp"
#include "clock.hpp"
#include "expression.hpp"
#include "memory_resource.hpp"
#include "object.hpp"
#include "pointer.hpp"
#include "processor/base.hpp"
#include <array>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ddwaf {

class jwt_decode : public structured_processor<jwt_decode> {
public:
    static constexpr std::array<std::string_view, 1> param_names{"inputs"};

    jwt_decode(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : structured_processor(
              std::move(id), std::move(expr), std::move(mappings), evaluate, output)
    {}

    owned_object eval_impl(const unary_argument<object_view> &input, processor_cache &cache,
        nonnull_ptr<memory::memory_resource> alloc, ddwaf::timer &deadline) const;
};

} // namespace ddwaf
