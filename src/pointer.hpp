// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstddef>
#include <stdexcept>

namespace ddwaf {

template <typename T> class nonnull_ptr {
public:
    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    nonnull_ptr(T *ptr) : ptr_(ptr)
    {
        static_assert(sizeof(nonnull_ptr<T>) == sizeof(T *));

        if (ptr_ == nullptr) [[unlikely]] {
            throw std::invalid_argument("nonnull_ptr<T> initialised with nullptr");
        }
    }

    nonnull_ptr(const nonnull_ptr &other) = default;
    nonnull_ptr &operator=(const nonnull_ptr &other) = default;
    nonnull_ptr(nonnull_ptr &&other) = default;
    nonnull_ptr &operator=(nonnull_ptr &&other) = default;
    ~nonnull_ptr() = default;

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    constexpr operator T &() const { return *get(); }

    nonnull_ptr(std::nullptr_t) = delete;
    nonnull_ptr &operator=(std::nullptr_t) = delete;

    constexpr T *operator->() const { return ptr_; }
    constexpr T &operator*() const { return *ptr_; }
    constexpr T *get() const { return ptr_; }

private:
    T *ptr_;
};

template <class T, class U>
constexpr bool operator==(const nonnull_ptr<T> &lhs, const nonnull_ptr<U> &rhs) noexcept
{
    return lhs.get() == rhs.get();
}

template <class T, class U>
constexpr bool operator!=(const nonnull_ptr<T> &lhs, const nonnull_ptr<U> &rhs) noexcept
{
    return lhs.get() != rhs.get();
}

template <class T, class U>
constexpr bool operator==(const nonnull_ptr<T> &lhs, const U *rhs) noexcept
{
    return lhs.get() == rhs;
}

template <class T, class U>
constexpr bool operator!=(const nonnull_ptr<T> &lhs, const U *rhs) noexcept
{
    return lhs.get() != rhs;
}

} // namespace ddwaf
