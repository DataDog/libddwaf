// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <vector>

#include "exception.hpp"
#include "expression.hpp"
#include "generator/base.hpp" // IWYU pragma: keep
#include "object_store.hpp"
#include "utils.hpp"

namespace ddwaf {

struct processor_target {
    target_index index;
    std::string name;
    std::vector<std::string> key_path{};
};

struct processor_mapping {
    std::vector<processor_target> inputs;
    processor_target output;
};

struct processor_cache {
    expression::cache_type expr_cache;
    std::unordered_set<target_index> generated;
};

class base_processor {
public:
    base_processor() = default;
    base_processor(const base_processor &) = delete;
    base_processor &operator=(const base_processor &) = delete;

    base_processor(base_processor &&rhs) noexcept = default;
    base_processor &operator=(base_processor &&rhs) noexcept = default;
    virtual ~base_processor() = default;

    virtual void eval(object_store &store, optional_ref<ddwaf_object> &derived,
        processor_cache &cache, ddwaf::timer &deadline) const = 0;

    virtual void get_addresses(std::unordered_map<target_index, std::string> &addresses) const = 0;
};

template <typename T> class processor : public base_processor {
public:
    processor(std::string id, T &&generator, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : id_(std::move(id)), generator_(std::move(generator)), expr_(std::move(expr)),
          mappings_(std::move(mappings)), evaluate_(evaluate), output_(output)
    {}

    processor(std::string id, std::shared_ptr<expression> expr,
        std::vector<processor_mapping> mappings, bool evaluate, bool output)
        : id_(std::move(id)), generator_(), expr_(std::move(expr)), mappings_(std::move(mappings)),
          evaluate_(evaluate), output_(output)
    {}

    processor(const processor &) = delete;
    processor &operator=(const processor &) = delete;

    processor(processor &&rhs) noexcept = default;
    processor &operator=(processor &&rhs) noexcept = default;
    ~processor() override = default;

    void eval(object_store &store, optional_ref<ddwaf_object> &derived, processor_cache &cache,
        ddwaf::timer &deadline) const override
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

            if (store.has_target(mapping.output.index) ||
                cache.generated.find(mapping.output.index) != cache.generated.end()) {
                continue;
            }

            auto [input, attr] = store.get_target(mapping.inputs[0].index);
            if (input == nullptr) {
                continue;
            }

            if (attr != object_store::attribute::ephemeral) {
                // Whatever the outcome, we don't want to try and generate it again
                cache.generated.emplace(mapping.output.index);
            }

            auto object = generator_.generate(input, deadline);
            if (object.type == DDWAF_OBJ_INVALID) {
                continue;
            }

            if (evaluate_) {
                store.insert(mapping.output.index, mapping.output.name, object, attr);
            }

            if (output_ && derived.has_value()) {
                ddwaf_object &output = derived.value();
                if (evaluate_) {
                    auto copy = ddwaf::object::clone(&object);
                    ddwaf_object_map_add(&output, mapping.output.name.c_str(), &copy);
                } else {
                    ddwaf_object_map_add(&output, mapping.output.name.c_str(), &object);
                }
            }
        }
    }
    [[nodiscard]] const std::string &get_id() const { return id_; }

    void get_addresses(std::unordered_map<target_index, std::string> &addresses) const override
    {
        expr_->get_addresses(addresses);
        for (const auto &mapping : mappings_) {
            for (const auto &input : mapping.inputs) { addresses.emplace(input.index, input.name); }
        }
    }

    // Used for testing
    T &generator() { return generator_; }

protected:
    std::string id_;
    T generator_;
    std::shared_ptr<expression> expr_;
    std::vector<processor_mapping> mappings_;
    bool evaluate_{false};
    bool output_{true};
};

} // namespace ddwaf
