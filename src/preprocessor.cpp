// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "preprocessor.hpp"
#include "ddwaf.h"
#include "exception.hpp"

namespace ddwaf {

void preprocessor::eval(object_store &store, ddwaf_object &derived, cache_type &cache, ddwaf::timer &deadline) const
{
    if (!cache.result) {
        std::vector<condition::ptr>::const_iterator cond_iter;
        bool run_on_new;
        if (cache.last_cond.has_value()) {
            cond_iter = *cache.last_cond;
            run_on_new = true;
        } else {
            cond_iter = conditions_.cbegin();
            run_on_new = false;
        }

        while (cond_iter != conditions_.cend()) {
            auto &&cond = *cond_iter;
            auto opt_match = cond->match(store, {}, run_on_new, {}, deadline);
            if (!opt_match.has_value()) {
                cache.last_cond = cond_iter;
                return;
            }

            run_on_new = false;
            cond_iter++;
        }

        cache.result = true;
    }

    for (const auto &mapping : mappings_) {
        if (deadline.expired()) {
            throw ddwaf::timeout_exception();
        }

        if (store.has_target(mapping.output)) {
            continue;
        }

        auto [input, attr] = store.get_target(mapping.input);
        if (input == nullptr) {
            continue;
        }

        auto object = generator_->generate(input);
        if (object.type == DDWAF_OBJ_INVALID) {
            continue;
        }

        if (output_) {
            auto copy = ddwaf::object::clone(&object);
            ddwaf_object_map_add(&derived, mapping.output_address.c_str(), &copy);
        }

        if (evaluate_) {
            store.insert(mapping.output, object);
        }

    }
}

} // namespace ddwaf
