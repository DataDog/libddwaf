// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <stdexcept>
#include <string_view>

#include "utils.hpp"

namespace ddwaf {
class semantic_version {
public:
    explicit semantic_version(std::string_view version) : str_(version)
    {
        version = parse_version_number(version, major_);
        version = parse_version_number(version, minor_);
        parse_version_number(version, patch_);

        number_ = major_ * 1000000 + minor_ * 1000 + patch_;
    }

    bool operator==(const semantic_version &other) const noexcept
    {
        return number_ == other.number_;
    }
    auto operator<=>(const semantic_version &other) const noexcept
    {
        return number_ <=> other.number_;
    }

    [[nodiscard]] unsigned major() const noexcept { return major_; }
    [[nodiscard]] unsigned minor() const noexcept { return minor_; }
    [[nodiscard]] unsigned patch() const noexcept { return patch_; }

    [[nodiscard]] unsigned number() const noexcept { return number_; }
    [[nodiscard]] const char *cstring() const noexcept { return str_.data(); }

protected:
    static std::string_view parse_version_number(std::string_view version, unsigned &number)
    {
        number = 0;

        if (version.empty()) {
            return {};
        }

        std::size_t i = 0;
        for (; i < version.size() && version[i] != '.'; ++i) {
            auto c = version[i];
            if (!ddwaf::isdigit(c)) {
                throw std::invalid_argument("invalid version syntax");
            }

            number = number * 10 + (c - '0');
        }

        return i < version.size() ? version.substr(i + 1) : std::string_view{};
    }

    std::string_view str_;
    unsigned number_{0};
    unsigned major_{0};
    unsigned minor_{0};
    unsigned patch_{0};
};

} // namespace ddwaf
