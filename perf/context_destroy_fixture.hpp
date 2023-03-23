// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog
// (https://www.datadoghq.com/). Copyright 2022 Datadog, Inc.

#pragma once

#include <ddwaf.h>
#include <vector>

#include "fixture_base.hpp"

namespace ddwaf::benchmark {

class context_destroy_fixture : public fixture_base {
public:
    context_destroy_fixture(ddwaf_handle handle, std::vector<ddwaf_object> &&objects);
    ~context_destroy_fixture() override;

    context_destroy_fixture(const context_destroy_fixture &) = delete;
    context_destroy_fixture &operator=(const context_destroy_fixture &) = delete;

    context_destroy_fixture(context_destroy_fixture &&) = delete;
    context_destroy_fixture &operator=(context_destroy_fixture &&) = delete;

    bool set_up() override;

    uint64_t test_main() override;

    void tear_down() override {}

protected:
    std::vector<ddwaf_object> objects_;
    ddwaf_handle handle_{nullptr};
    ddwaf_context ctx_{nullptr};
};

} // namespace ddwaf::benchmark
