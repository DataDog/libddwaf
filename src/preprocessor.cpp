// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "preprocessor.hpp"
#include "ddwaf.h"
#include "exception.hpp"

namespace ddwaf {

void preprocessor::eval(object_store &store, optional_ref<ddwaf_object> &derived, cache_type &cache,
    ddwaf::timer &deadline) const
{
    // No result structure, but this preprocessor only produces derived objects
    // so it makes no sense to evaluate.
    if (!derived.has_value() && !evaluate_ && output_) {
        return;
    }

    if (!expression::get_result(cache) && !expr_->eval(cache, store, {}, {}, deadline)) {
        return;
    }

    for (const auto &mapping : mappings_) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (store.has_target(mapping.output)) {
            continue;
        }

        auto *input = store.get_target(mapping.input);
        if (input == nullptr) {
            continue;
        }

        auto object = generator_->generate(input);
        if (object.type == DDWAF_OBJ_INVALID) {
            continue;
        }

        if (evaluate_) {
            store.insert(mapping.output, object);
        }

        if (output_ && derived.has_value()) {
            ddwaf_object &output = derived.value();
            if (evaluate_) {
                auto copy = ddwaf::object::clone(&object);
                ddwaf_object_map_add(&output, mapping.output_address.c_str(), &copy);
            } else {
                ddwaf_object_map_add(&output, mapping.output_address.c_str(), &object);
            }
        }
    }
}

} // namespace ddwaf
