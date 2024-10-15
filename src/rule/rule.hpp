// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "clock.hpp"
#include "event.hpp"
#include "exclusion/common.hpp"
#include "expression.hpp"
#include "matcher/base.hpp"
#include "object_store.hpp"
#include "rule/base.hpp"

namespace ddwaf {

class rule : public base_rule {
public:
    enum class source_type : uint8_t { base = 1, user = 2 };

    using cache_type = expression::cache_type;

    rule(std::string id, std::string name, std::unordered_map<std::string, std::string> tags,
        std::shared_ptr<expression> expr, std::vector<std::string> actions = {},
        bool enabled = true, source_type source = source_type::base)
        : base_rule(std::move(id), std::move(name), std::move(tags), std::move(expr),
              std::move(actions), enabled),
          source_(source)
    {}

    rule(const rule &) = delete;
    rule &operator=(const rule &) = delete;

    rule(rule &&rhs) noexcept = default;
    rule &operator=(rule &&rhs) noexcept = default;

    ~rule() override = default;

    virtual std::optional<event> match(const object_store &store, cache_type &cache,
        const exclusion::object_set_ref &objects_excluded,
        const std::unordered_map<std::string, std::shared_ptr<matcher::base>> &dynamic_matchers,
        ddwaf::timer &deadline) const
    {
        if (expression::get_result(cache)) {
            // An event was already produced, so we skip the rule
            return std::nullopt;
        }

        auto res = expr_->eval(cache, store, objects_excluded, dynamic_matchers, deadline);
        if (!res.outcome) {
            return std::nullopt;
        }

        return {ddwaf::event{this, expression::get_matches(cache), res.ephemeral, {}}};
    }

    source_type get_source() const { return source_; }

protected:
    source_type source_;
};

} // namespace ddwaf
