// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "clock.hpp"
#include "cow_string.hpp"
#include "exception.hpp"
#include "exclusion/common.hpp"
#include "iterator.hpp"
#include "object.hpp"
#include "transformer/base.hpp"
#include "transformer/manager.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

namespace ddwaf {

template <typename IteratorType = kv_iterator> class transforming_iterator {
public:
    explicit transforming_iterator(object_view obj, std::span<const transformer_id> transformers,
        const object_set_ref &exclude, ddwaf::timer &deadline)
        : it_(obj, {}, exclude), transformers_(transformers), deadline_(deadline)
    {
        advance_to_transformable_object();
    }

    ~transforming_iterator() = default;

    transforming_iterator(const transforming_iterator &) = delete;
    transforming_iterator(transforming_iterator &&) = delete;

    transforming_iterator &operator=(const transforming_iterator &) = delete;
    transforming_iterator &operator=(transforming_iterator &&) = delete;

    // The returned view is only valid until the next call to operator++, as the
    // underlying buffer is replaced on every advance
    [[nodiscard]] std::string_view current_value() const
    {
        if (current_param_.has_value()) {
            return static_cast<std::string_view>(current_param_.value());
        }
        return {};
    }

    // Wraps the current value in a string object, for the benefit of callers
    // which require an object rather than a view. As with current_value(), the
    // returned object is only valid until the next call to operator++.
    [[nodiscard]] object_view operator*()
    {
        auto value = current_value();
        // A transformer can yield an empty string with no underlying buffer,
        // e.g. remove_comments on a value which is entirely a comment. String
        // objects are expected to always provide a valid pointer, so an empty
        // literal is used instead.
        const char *data = value.data() != nullptr ? value.data() : "";
        current_object_ = owned_object::make_string_literal(data, value.size());
        return current_object_;
    }

    bool operator++()
    {
        ++it_;
        return advance_to_transformable_object();
    }

    [[nodiscard]] explicit operator bool() const { return static_cast<bool>(it_); }

    [[nodiscard]] std::vector<std::variant<std::string_view, int64_t>> get_current_path() const
    {
        return it_.get_current_path();
    }

protected:
    // Advances the underlying iterator until it lands on a string, which is
    // then transformed and made the current value. Returns false if the
    // iterator was exhausted before finding one.
    bool advance_to_transformable_object()
    {
        for (; it_; ++it_) {
            // Objects which can't be transformed are skipped within this
            // iterator, so the deadline must be evaluated here rather than
            // relying on the caller doing so once per yielded value
            if (deadline_.expired()) {
                throw ddwaf::timeout_exception();
            }

            const object_view current_obj = *it_;
            if (!current_obj.is_string()) {
                continue;
            }

            current_param_ = transformer::manager::transform(current_obj, transformers_);
            if (!current_param_.has_value()) {
                current_param_ = cow_string{current_obj.template as<std::string_view>()};
            }

            return true;
        }

        return false;
    }

    std::optional<cow_string> current_param_;
    owned_object current_object_;
    IteratorType it_;
    std::span<const transformer_id> transformers_;
    ddwaf::timer &deadline_;
};

} // namespace ddwaf
