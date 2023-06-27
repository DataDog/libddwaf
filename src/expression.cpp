// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <exception.hpp>
#include <expression.hpp>
#include <log.hpp>
#include <memory>

namespace ddwaf {

namespace {

bool evaluate_condition()
{
    
}

}

bool expression::eval(cache_type &cache, const object_store &store,
    const std::unordered_set<const ddwaf_object *> &objects_excluded,
    ddwaf::timer &deadline) const
{
    for (unsigned i = 0; i < conditions_.size(); ++i) {


    }
}


} // namespace ddwaf
