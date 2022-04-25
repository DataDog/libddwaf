// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2022 Datadog, Inc.

#pragma once

#include <clock.hpp>

namespace ddwaf::benchmark
{

class fixture_base
{
public:
    fixture_base() = default;
    virtual ~fixture_base() = default;

    virtual bool global_set_up() { return true; }
    virtual bool set_up() { return true; }

    virtual uint64_t test_main() const = 0;

    virtual void tear_down() {};
    virtual void global_tear_down() {};
};

}
