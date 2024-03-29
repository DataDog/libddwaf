// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <functional>
#include <map>
#include <memory>
#include <utility>
#include <vector>

#include "fixture_base.hpp"
#include "settings.hpp"

namespace ddwaf::benchmark {
class runner {
public:
    struct test_result {
        // uint64_t average, p0, p50, p75, p90, p95, p99, p100, sd;
        std::vector<uint64_t> samples;
    };

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    explicit runner(std::string scenario, settings &s)
        : scenario_(std::move(scenario)), iterations_(s.iterations),
          warmup_iterations_(s.warmup_iterations)
    {}

    template <typename F, typename... Args>
    void register_fixture(const std::string &name, Args &&...args)
    {
        tests_.emplace(name, std::make_unique<F>(std::forward<Args &&>(args)...));
    }

    std::map<std::string, test_result> run();

protected:
    std::map<std::string, test_result> run_st();
    std::map<std::string, test_result> run_mt();

    std::string scenario_;
    unsigned iterations_;
    unsigned warmup_iterations_;
    std::unordered_map<std::string, std::unique_ptr<fixture_base>> tests_;
};

} // namespace ddwaf::benchmark
