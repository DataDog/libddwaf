// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#pragma once

#include <random>
#include <memory>

namespace ddwaf::benchmark
{

class random
{
public:
    static void seed(unsigned long value)
    {
        rng_ = std::make_unique<std::mt19937>(value);
    }

    static unsigned long get()
    {
        if (!rng_) {
            rng_ = std::make_unique<std::mt19937>();
        }
        return (*rng_)();
    }

    static std::mt19937& get_rng()
    {
        return *rng_;
    }
protected:
    static std::unique_ptr<std::mt19937> rng_;
};

}
