// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <cstdint>
#include <fmt/format.h>
#include <string>
#include <string_view>

namespace ddwaf {
class semantic_version {
public:
    explicit semantic_version(std::string_view version);

    semantic_version(semantic_version &&other) = default;
    semantic_version &operator=(semantic_version &&other) noexcept = default;
    semantic_version(const semantic_version &other) = default;
    semantic_version &operator=(const semantic_version &other) noexcept = default;
    ~semantic_version() = default;

    bool operator==(const semantic_version &other) const noexcept
    {
        return number_ == other.number_;
    }
    auto operator<=>(const semantic_version &other) const noexcept
    {
        return number_ <=> other.number_;
    }

    [[nodiscard]] unsigned number() const noexcept { return number_; }
    [[nodiscard]] const char *cstring() const noexcept { return str_.c_str(); }
    [[nodiscard]] std::string_view string() const noexcept { return str_; }
    [[nodiscard]] uint16_t major() const noexcept { return major_; }
    [[nodiscard]] uint16_t minor() const noexcept { return minor_; }
    [[nodiscard]] uint16_t patch() const noexcept { return patch_; }

    static semantic_version max()
    {
        static const semantic_version v{"999.999.999", 999, 999, 999, 999999999};
        return v;
    }

    static semantic_version min()
    {
        static const semantic_version v{"0.0.0", 0, 0, 0, 0};
        return v;
    }

protected:
    semantic_version(
        // NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
        std::string_view str, uint16_t major, uint16_t minor, uint16_t patch, uint32_t number)
        : str_(str), major_(major), minor_(minor), patch_(patch), number_(number)
    {}

    static bool parse_number(std::string_view str, uint16_t &output);

    std::string str_;
    uint16_t major_{0};
    uint16_t minor_{0};
    uint16_t patch_{0};
    uint32_t number_{0};
};

template <> struct fmt::formatter<semantic_version> : fmt::formatter<std::string_view> {
    // Use the parse method from the base class formatter
    template <typename FormatContext> auto format(semantic_version &v, FormatContext &ctx) const
    {
        return fmt::formatter<std::string_view>::format(v.string(), ctx);
    }
};

} // namespace ddwaf
