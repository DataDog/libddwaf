// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include "action_mapper.hpp"
#include "attribute_collector.hpp"
#include "obfuscator.hpp"
#include "object.hpp"
#include "rule.hpp"

namespace ddwaf {

// NOLINTBEGIN(cppcoreguidelines-avoid-const-or-ref-data-members)
struct result_components {
    borrowed_object events;
    borrowed_object actions;
    borrowed_object duration;
    borrowed_object timeout;
    borrowed_object attributes;
    borrowed_object keep;
};
// NOLINTEND(cppcoreguidelines-avoid-const-or-ref-data-members)

class result_serializer {
public:
    explicit result_serializer(const match_obfuscator &obfuscator, const action_mapper &actions)
        : obfuscator_(obfuscator), actions_(actions)
    {}

    void serialize(const object_store &store, std::vector<rule_result> &results,
        attribute_collector &collector, const timer &deadline, result_components output) const;

    static std::pair<owned_object, result_components> initialise_result_object();

protected:
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const match_obfuscator &obfuscator_;
    // NOLINTNEXTLINE(cppcoreguidelines-avoid-const-or-ref-data-members)
    const action_mapper &actions_;
};

} // namespace ddwaf
