// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2025 Datadog, Inc.

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <string_view>

#include "semver.hpp"
#include "utils.hpp"

namespace ddwaf {

semantic_version::semantic_version(std::string_view version) : str_(version)
{
    // The expected version string is: xxx.yyy.zzz[-label]
    // We only try to extract xxx, yyy and zzz, while discarding the label.
    // Each element can be 1 to 3 digits long, but no longer.
    // Any deviation from this will be rejected.

    // Major
    std::size_t start = 0;
    auto end = version.find('.');
    if (end == std::string_view::npos) {
        throw std::invalid_argument("invalid version syntax");
    }
    auto major_str = version.substr(start, end - start);
    if (major_str.empty() || major_str.size() > 3 || !parse_number(major_str, major_)) {
        throw std::invalid_argument("invalid major version: " + std::string{major_str});
    }

    // Minor
    start = end + 1;
    end = version.find('.', start);
    if (end == std::string_view::npos) {
        throw std::invalid_argument("invalid version syntax");
    }
    auto minor_str = version.substr(start, end - start);
    if (minor_str.empty() || minor_str.size() > 3 || !parse_number(minor_str, minor_)) {
        throw std::invalid_argument("invalid minor version: " + std::string{minor_str});
    }

    // Patch
    start = end + 1;
    end = version.find('-', start);
    auto patch_str = version.substr(start, end - start);
    if (patch_str.empty() || patch_str.size() > 3 || !parse_number(patch_str, patch_)) {
        throw std::invalid_argument("invalid patch version: " + std::string{patch_str});
    }

    number_ = major_ * 1000000 + minor_ * 1000 + patch_;
}

bool semantic_version::parse_number(std::string_view str, uint16_t &output)
{
    if (auto [res, value] = from_string<uint16_t>(str); res) {
        output = value;
        return true;
    }
    return false;
}

} // namespace ddwaf
