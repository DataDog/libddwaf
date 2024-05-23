// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "processor.hpp"
#include "ddwaf.h"
#include "exception.hpp"

namespace ddwaf {

void processor::eval(object_store &store, optional_ref<ddwaf_object> &derived,
    processor_cache &cache, ddwaf::timer &deadline) const
{
    // No result structure, but this processor only produces derived objects
    // so it makes no sense to evaluate.
    if (!derived.has_value() && !evaluate_ && output_) {
        return;
    }

    DDWAF_DEBUG("Evaluating processor '{}'", id_);

    if (!expr_->eval(cache.expr_cache, store, {}, {}, deadline).outcome) {
        return;
    }

    for (const auto &mapping : mappings_) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (store.has_target(mapping.output) ||
            cache.generated.find(mapping.output) != cache.generated.end()) {
            continue;
        }

        auto [input, attr] = store.get_target(mapping.input);
        if (input == nullptr) {
            continue;
        }

        if (attr != object_store::attribute::ephemeral) {
            // Whatever the outcome, we don't want to try and generate it again
            cache.generated.emplace(mapping.output);
        }

        auto object = generator_->generate(input, scanners_, deadline);
        if (object.type == DDWAF_OBJ_INVALID) {
            continue;
        }

        if (evaluate_) {
            store.insert(mapping.output, mapping.output_address, object, attr);
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
