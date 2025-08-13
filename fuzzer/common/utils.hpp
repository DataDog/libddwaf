// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#pragma once

#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>

namespace ddwaf_afl {

// Utility to convert raw bytes to string_view
inline std::string_view bytes_to_string_view(const uint8_t *data, size_t size)
{
    return std::string_view{reinterpret_cast<const char *>(data), size};
}

// Utility to split input data into multiple parts (useful for complex fuzzers)
class InputSplitter {
public:
    InputSplitter(const uint8_t *data, size_t size) : data_(data), size_(size), offset_(0) {}

    template <typename T> T get()
    {
        if (offset_ + sizeof(T) > size_) {
            return T{};
        }
        T value;
        std::memcpy(&value, data_ + offset_, sizeof(T));
        offset_ += sizeof(T);
        return value;
    }

    std::string_view get_string()
    {
        if (offset_ >= size_) {
            return {};
        }

        auto length = get<uint16_t>();
        if (offset_ + length > size_) {
            length = size_ - offset_;
        }

        if (length == 0) {
            return {};
        }

        std::string_view result{reinterpret_cast<const char *>(data_ + offset_), length};
        offset_ += length;
        return result;
    }

    std::string_view get_remaining()
    {
        if (offset_ >= size_) {
            return {};
        }
        std::string_view result{reinterpret_cast<const char *>(data_ + offset_), size_ - offset_};
        offset_ = size_;
        return result;
    }

    bool has_data() const { return offset_ < size_; }

    size_t remaining_bytes() const { return offset_ < size_ ? size_ - offset_ : 0; }

private:
    const uint8_t *data_;
    size_t size_;
    size_t offset_;
};

// Simple serializer for complex input formats
class InputSerializer {
public:
    InputSerializer() = default;

    void add_string(std::string_view str)
    {
        uint16_t length = static_cast<uint16_t>(str.size());
        data_.insert(data_.end(), reinterpret_cast<const uint8_t *>(&length),
            reinterpret_cast<const uint8_t *>(&length) + sizeof(length));
        data_.insert(data_.end(), reinterpret_cast<const uint8_t *>(str.data()),
            reinterpret_cast<const uint8_t *>(str.data()) + str.size());
    }

    template <typename T> void add_value(const T &value)
    {
        data_.insert(data_.end(), reinterpret_cast<const uint8_t *>(&value),
            reinterpret_cast<const uint8_t *>(&value) + sizeof(value));
    }

    const std::vector<uint8_t> &data() const { return data_; }
    const uint8_t *raw_data() const { return data_.data(); }
    size_t size() const { return data_.size(); }

private:
    std::vector<uint8_t> data_;
};

// Memory resource setup (common across fuzzers)
inline void setup_memory_resource()
{
    // This would typically set up ddwaf memory resource
    // For now, we'll assume it's handled elsewhere
}

// Prevent compiler optimization of results
template <typename T> inline void prevent_optimization(T &value)
{
    asm volatile("" : "+m"(value) : : "memory");
}

// Random buffer utility for processor fuzzers
class random_buffer {
public:
    random_buffer(const uint8_t *bytes, size_t size) : bytes_(bytes), size_(size) {}

    template <typename T> T get()
    {
        if ((index_ + sizeof(T)) > size_) {
            return {};
        }

        T value;
        std::memcpy(&value, &bytes_[index_], sizeof(T));
        index_ += sizeof(T) + (sizeof(T) % 2);
        return value;
    }

    template <> bool get()
    {
        if (index_ >= size_) {
            return false;
        }

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        bool value = bytes_[index_] > 0;
        index_ += 2;
        return value;
    }

    template <> std::string_view get()
    {
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

} // namespace ddwaf_afl