// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdint>

namespace ddwaf {

enum class platform : uint8_t { unknown = 0, linux, windows, macos };

struct system_platform {
    static platform current() { return platform_override; }

    static void override_platform(platform p) { platform_override = p; }

    static platform platform_override;
};

struct system_platform_override {
    explicit system_platform_override(platform p) : prev(system_platform::current())
    {
        system_platform::override_platform(p);
    }

    ~system_platform_override() { system_platform::override_platform(prev); }

    system_platform_override(const system_platform_override &) = delete;
    system_platform_override(system_platform_override &&) = delete;

    system_platform_override &operator=(const system_platform_override &) = delete;
    system_platform_override &operator=(system_platform_override &&) = delete;

    platform prev;
};
} // namespace ddwaf
