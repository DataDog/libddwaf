// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include "builder/matcher_builder.hpp"
#include "configuration/common/configuration.hpp"
#include "matcher/base.hpp"
#include "matcher/exact_match.hpp"
#include "matcher/ip_match.hpp"
#include <memory>

namespace ddwaf {

std::shared_ptr<matcher::base> matcher_builder::build(const merged_data_spec &data)
{
    std::shared_ptr<matcher::base> matcher;
    if (data.type == data_type::ip_with_expiration) {
        matcher = std::make_shared<matcher::ip_match>(data.values);
    } else if (data.type == data_type::data_with_expiration) {
        matcher = std::make_shared<matcher::exact_match>(data.values);
    }

    return matcher;
}

} // namespace ddwaf
