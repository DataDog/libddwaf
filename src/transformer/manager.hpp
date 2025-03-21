// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <span>

#include "object.hpp"
#include "transformer/base.hpp"

namespace ddwaf::transformer {

// For now the manager can only be used for transforming a single object
// using multiple transformers, hence why all methods are static. In the future
// this will also host the cache and will have to be shared by all conditions.
class manager {
public:
    static bool transform(object_view source, owned_object &destination,
        const std::span<const transformer_id> &transformers);
};

} // namespace ddwaf::transformer
