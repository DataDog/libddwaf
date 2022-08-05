// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <rule_processor/base.hpp>
#include <ip_utils.hpp>
#include <memory>
#include <radixlib.h>

namespace ddwaf::rule_processor
{

class ip_match : public base
{
public:
    explicit ip_match(const std::vector<std::string_view> &ip_list);
    explicit ip_match(const std::vector<std::pair<std::string_view,uint64_t>> &ip_list);

    std::string_view name() const override { return "ip_match"; }

    std::optional<event::match> match(std::string_view str) const override;
protected:
    std::unique_ptr<radix_tree_t, decltype(&radix_free)> rtree_;
};

}
