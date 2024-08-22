// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <chrono>
#include <iostream>
#include <map>
#include <mutex>
#include <string>
#include <type_traits>
#include <vector>

#include "traits.hpp"

namespace ddwaf {

// Perhaps this should use an std::chrono::time_point<T> instead
template <typename T>
    requires is_duration<T>
class sliding_window_counter {
public:
    sliding_window_counter() = default;
    explicit sliding_window_counter(T period, std::size_t max_window_size = 100) : period_(period)
    {
        time_points_.resize(max_window_size);
    }

    uint64_t add_timepoint_and_count(T point)
    {
        // Discard old elements
        update_count(point);

        // Check if the latest element is beyond the current one (concurrent writers)
        auto index = decrement(right);
        if (buckets > 0 && time_points_[index].point > point) {
            ++time_points_[index].count;
            return ++count;
        }

        if (buckets < time_points_.size()) {
            // Add a new element
            time_points_[right].point = point;
            time_points_[right].count = 1;
            right = increment(right);
            ++count;
            ++buckets;
        } else if (buckets == time_points_.size()) {
            // Discard the oldest one
            time_points_[right].point = point;
            count -= (time_points_[right].count - 1);
            time_points_[right].count = 1;
            right = increment(right);
            left = increment(left);
        }

        return count;
    }

    T last_timepoint() const
    {
        if (buckets == 0) {
            [[unlikely]] return static_cast<T>(0);
        }

        auto index = decrement(right);
        return time_points_[index].point;
    }

    uint64_t update_count(T point)
    {
        // Discard old elements
        auto window_begin = point - period_;
        while (buckets > 0 && time_points_[left].point <= window_begin) {
            count -= time_points_[left].count;
            --buckets;
            left = increment(left);
        }
        return count;
    }

    void reset() { left = right = count = buckets = 0; }

protected:
    [[nodiscard]] uint64_t increment(uint64_t value) const
    {
        return (value + 1) % time_points_.size();
    }

    [[nodiscard]] uint64_t decrement(uint64_t value) const
    {
        return (value + time_points_.size() - 1) % time_points_.size();
    }

    struct time_bucket {
        T point;
        uint64_t count;
    };

    std::chrono::milliseconds period_{};
    std::vector<time_bucket> time_points_;
    uint64_t left{0};
    uint64_t right{0};
    uint64_t count{0};
    uint64_t buckets{0};
};

using sliding_window_counter_ms = sliding_window_counter<std::chrono::milliseconds>;

} // namespace ddwaf
