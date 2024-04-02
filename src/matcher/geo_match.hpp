// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <memory>
#include <unordered_set>
#include <vector>

#include "matcher/base.hpp"
#include "maxminddb/maxminddb.h"

namespace ddwaf::matcher {

class geo_match : public base_impl<geo_match> {
public:
    geo_match() = default;
    explicit geo_match(
        std::unordered_set<std::string> countries, const std::string &path = "ip-metadata.mmdb")
        : countries_(std::move(countries))
    {
        int res = MMDB_open(path.c_str(), MMDB_MODE_MMAP, &mmdb_);
        if (res != MMDB_SUCCESS) {
            throw std::runtime_error("failed to instantiate mmdb: " + path);
        }
    }

    ~geo_match() override { MMDB_close(&mmdb_); }

    geo_match(const geo_match &) = delete;
    geo_match(geo_match &&) = default;
    geo_match &operator=(const geo_match &) = delete;
    geo_match &operator=(geo_match &&) = default;

protected:
    static constexpr std::string_view to_string_impl() { return ""; }
    static constexpr std::string_view name_impl() { return "geo_match"; }
    static constexpr DDWAF_OBJ_TYPE supported_type_impl() { return DDWAF_OBJ_STRING; }

    [[nodiscard]] std::pair<bool, std::string> match_impl(std::string_view str) const;

    MMDB_s mmdb_{};
    std::unordered_set<std::string> countries_{};

    friend class base_impl<geo_match>;
};

} // namespace ddwaf::matcher
