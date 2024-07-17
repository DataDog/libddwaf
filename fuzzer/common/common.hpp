// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#include <cstdint>
#include <cstdlib>
#include <string_view>

class random_buffer {
public:
    random_buffer(const uint8_t *bytes, size_t size) : bytes_(bytes), size_(size) {}

    template <typename T> T get()
    {
        if ((index_ + sizeof(T)) >= size_) {
            return {};
        }

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const T *value = reinterpret_cast<const T *>(&bytes_[index_]);
        index_ += sizeof(T) + (sizeof(T) % 2);
        return *value;
    }

    template <> std::string_view get()
    {
        if ((index_ + sizeof(uint16_t)) >= size_) {
            return "";
        }

        auto size = std::min(static_cast<size_t>(get<uint16_t>()) % 4096, size_ - index_);

        if (size == 0) {
            return "";
        }

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        const auto *ptr = reinterpret_cast<const char *>(&bytes_[index_]);
        index_ += size + size % 2;
        return {ptr, size};
    }

protected:
    const uint8_t *bytes_;
    size_t size_;
    size_t index_{0};
};
