// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#pragma once

#include <array>

#include "fixture_base.hpp"
#include "object_generator.hpp"

namespace ddwaf::benchmark
{

class run_fixture : public fixture_base
{
public:
    run_fixture(unsigned iterations, ddwaf_handle handle,
        const object_generator::limits &limits);
    ~run_fixture() override;

    bool set_up() override;

    uint64_t test_main() override;

    void tear_down() override;

protected:
    static constexpr std::size_t max_objects = 100;

    std::size_t num_objects_{max_objects};
    std::array<ddwaf_object, max_objects> objects_;
    ddwaf_handle handle_{nullptr};
    ddwaf_context ctx_{nullptr};
};

}
