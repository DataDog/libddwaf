// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <memory>
#include <random>

namespace ddwaf::benchmark {

class random {
public:
    static void seed(uint64_t value)
    {
        seed_ = value;
        rng_ = std::make_unique<std::mt19937>(value);
    }

    static uint64_t get()
    {
        if (!rng_) {
            rng_ = std::make_unique<std::mt19937>();
        }
        return (*rng_)();
    }

    static bool get_bool()
    {
        if (!rng_) {
            rng_ = std::make_unique<std::mt19937>();
        }
        return ((*rng_)() % 2) == 1;
    }

    static std::mt19937 &get_rng() { return *rng_; }

    static uint64_t get_seed() { return seed_; }

protected:
    static uint64_t seed_;
    static std::unique_ptr<std::mt19937> rng_;
};

} // namespace ddwaf::benchmark
