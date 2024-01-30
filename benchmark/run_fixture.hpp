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

class run_fixture : public fixture_base {
public:
    run_fixture(ddwaf_handle handle, ddwaf_object object);
    ~run_fixture() override { ddwaf_object_free(&object_); }

    run_fixture(const run_fixture &) = delete;
    run_fixture &operator=(const run_fixture &) = delete;

    run_fixture(run_fixture &&) = delete;
    run_fixture &operator=(run_fixture &&) = delete;

    bool set_up() override;

    uint64_t test_main() override;

    void tear_down() override;

protected:
    ddwaf_object object_;
    ddwaf_handle handle_{nullptr};
    ddwaf_context ctx_{nullptr};
};

} // namespace ddwaf::benchmark
