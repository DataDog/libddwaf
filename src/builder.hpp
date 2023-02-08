// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <manifest.hpp>
#include <parameter.hpp>
#include <rule.hpp>
#include <ruleset.hpp>
#include <ruleset_info.hpp>
#include <string>
#include <unordered_map>
#include <vector>


namespace ddwaf
{

class builder {
public:
/*    builder() = default;*/
    /*~builder() = default;*/
    /*builder(builder&&) = default;*/
    /*builder(const builder&) = delete;*/
    /*builder& operator=(builder&&) = default;*/
    /*builder& operator=(const builder&) = delete;*/

    static std::shared_ptr<ruleset> build(parameter object, ruleset_info &info, object_limits limits);

protected:

};

} // namespace ddwaf
