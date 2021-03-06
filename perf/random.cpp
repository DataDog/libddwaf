// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#include "random.hpp"

namespace ddwaf::benchmark {

uint64_t random::seed_ = 0;

// NOLINTNEXTLINE(cert-err58-cpp)
std::unique_ptr<std::mt19937> random::rng_ = std::make_unique<std::mt19937>();

} // namespace ddwaf::benchmark
