// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <type_traits>
#include <vector>

namespace ddwaf {

template <typename T>
concept is_duration = std::is_same_v<std::chrono::duration<typename T::rep, typename T::period>, T>;

// Perhaps this should use an std::chrono::time_point<T> instead
template <typename T>
    requires is_duration<T>
class timed_counter {
public:
    timed_counter() = default;
    explicit timed_counter(T period, std::size_t max_window_size = 100) : period_(period)
    {
        time_points_.resize(max_window_size);
    }

    std::size_t add_timepoint_and_count(T point)
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

    std::size_t update_count(T point)
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
    [[nodiscard]] std::size_t increment(std::size_t value) const
    {
        return (value + 1) % time_points_.size();
    }

    [[nodiscard]] std::size_t decrement(std::size_t value) const
    {
        return (value + time_points_.size() - 1) % time_points_.size();
    }

    struct time_bucket {
        T point;
        std::size_t count;
    };

    std::chrono::milliseconds period_{};
    std::vector<time_bucket> time_points_;
    std::size_t left{0};
    std::size_t right{0};
    std::size_t count{0};
    std::size_t buckets{0};
};

template <typename T>
    requires is_duration<T>
class timed_counter_ts : protected timed_counter<T> {
public:
    timed_counter_ts() = default;
    explicit timed_counter_ts(T period, std::size_t max_window_size = 100)
        : timed_counter<T>(period, max_window_size)
    {}
    std::size_t add_timepoint_and_count(T point)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        return timed_counter<T>::add_timepoint_and_count(point);
    }

    T last_timepoint() const
    {
        std::lock_guard<std::mutex> lock(mtx_);
        return timed_counter<T>::last_timepoint();
    }

    std::size_t update_count(T point)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        return timed_counter<T>::update_count(point);
    }

    void reset()
    {
        std::lock_guard<std::mutex> lock(mtx_);
        timed_counter<T>::reset();
    }

protected:
    mutable std::mutex mtx_;
};

template <typename Key, typename Duration>
    requires is_duration<Duration>
class indexed_timed_counter_ts {
public:
    indexed_timed_counter_ts() = default;
    explicit indexed_timed_counter_ts(
        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
        Duration period, std::size_t max_index_size = 32, std::size_t max_window_size = 100)
        : period_(period), max_index_size_(max_index_size), max_window_size_(max_window_size)
    {}

    template <typename T>
        requires std::is_constructible_v<T, Key>
    std::size_t add_timepoint_and_count(T key, Duration point)
    {
        std::lock_guard<std::mutex> lock(mtx_);
        auto it = index_.find(key);
        if (it == index_.end()) {
            if (index_.size() == max_index_size_) {
                remove_oldest_entry(point);
            }

            auto [new_it, res] =
                index_.emplace(Key{key}, timed_counter<Duration>{period_, max_window_size_});
            if (!res) {
                return 0;
            }

            it = new_it;
        }

        return it->second.add_timepoint_and_count(point);
    }

protected:
    void remove_oldest_entry(Duration point)
    {
        using iterator_type = typename decltype(index_)::iterator;

        Duration max_delta{0};
        iterator_type oldest_it;
        for (auto it = index_.begin(); it != index_.end(); ++it) {
            auto window_last = it->second.last_timepoint();
            auto delta = point - window_last;
            if (delta > max_delta) {
                max_delta = delta;
                oldest_it = it;
            }
        }

        index_.erase(oldest_it);
    }

    Duration period_;
    std::size_t max_index_size_{};
    std::size_t max_window_size_{};
    std::map<Key, timed_counter<Duration>, std::less<>> index_;
    mutable std::mutex mtx_;
};

using timed_counter_ts_ms = timed_counter_ts<std::chrono::milliseconds>;
using indexed_timed_counter_ts_ms =
    indexed_timed_counter_ts<std::string, std::chrono::milliseconds>;

} // namespace ddwaf
