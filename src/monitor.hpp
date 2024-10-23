// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <mutex>
namespace ddwaf {

template <typename T> class monitor {
public:
    template <typename... Args> explicit monitor(Args... args) : underlying_value_(args...) {}

    class locked_monitor {
    public:
        explicit locked_monitor(monitor &m) : m_(m), lock_(m.mtx_) {}
        T *operator->() { return &m_.underlying_value_; }

    protected:
        monitor &m_;
        std::unique_lock<std::mutex> lock_;
    };

    locked_monitor operator->() { return locked_monitor{*this}; }

protected:
    std::mutex mtx_{};
    T underlying_value_;
};

} // namespace ddwaf
