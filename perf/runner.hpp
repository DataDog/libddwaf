// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#pragma once

#include <functional>
#include <memory>
#include <vector>

#include "fixture_base.hpp"

namespace ddwaf::benchmark
{
class runner
{
public:
    runner() = default;

    template <typename F, typename... Args>
    void register_fixture(const std::string &name, std::size_t iterations, Args... args)
    {
        tests_.push_back({name, std::make_unique<F>(args...), iterations});
    }

    void run();

protected:
    struct runner_test {
        std::string name;
        std::unique_ptr<fixture_base> f;
        std::size_t iterations;

        using ref = std::reference_wrapper<runner_test>;
    };

    std::vector<runner_test> tests_;
};

}
