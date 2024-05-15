// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory_resource>
#include <string_view>

namespace ddwaf {

// This class mainly wraps a c-string and a memory resource so that
// it can be properly freed
class string_wrapper {
public:
    string_wrapper() = default;

    // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
    string_wrapper(char *str, std::size_t length, std::size_t allocated_length,
        std::pmr::memory_resource *alloc = std::pmr::new_delete_resource())
        : str_(str), length_(length), allocated_length_(allocated_length), alloc_(alloc)
    {}

    string_wrapper(const string_wrapper &) = delete;
    string_wrapper &operator=(const string_wrapper &) = delete;

    string_wrapper(string_wrapper &&other) noexcept
        : str_(other.str_), length_(other.length_), allocated_length_(other.allocated_length_),
          alloc_(other.alloc_)
    {
        other.str_ = nullptr;
        other.length_ = 0;
        other.allocated_length_ = 0;
        other.alloc_ = nullptr;
    }
    string_wrapper &operator=(string_wrapper &&other) noexcept
    {
        str_ = other.str_;
        length_ = other.length_;
        allocated_length_ = other.allocated_length_;
        alloc_ = other.alloc_;
        other.str_ = nullptr;
        other.length_ = 0;
        other.allocated_length_ = 0;
        other.alloc_ = nullptr;
        return *this;
    }

    ~string_wrapper()
    {
        if (alloc_ != nullptr) {
            alloc_->deallocate(str_, allocated_length_, alignof(char));
        }
    }

    [[nodiscard]] bool has_value() const noexcept { return str_ != nullptr; }

    [[nodiscard]] std::string_view view() const { return {str_, length_}; }

protected:
    char *str_{nullptr};
    std::size_t length_{0};
    std::size_t allocated_length_{0};
    std::pmr::memory_resource *alloc_{nullptr};
};

} // namespace ddwaf
