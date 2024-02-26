// Unless explicitly stated otherwise all files in this repository are
// dual-licensed under the Apache-2.0 License or BSD-3-Clause License.
//
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2021 Datadog, Inc.

#pragma once

#include <optional>
#include <string_view>

namespace ddwaf {

// https://datatracker.ietf.org/doc/html/rfc3986#section-3
struct uri_decomposed {
    std::string_view scheme;
    struct {
        std::size_t index;
        std::size_t host_index;
        bool ipv6_host{false};
        std::string_view userinfo{};
        std::string_view host{};
        std::string_view port{};
        std::string_view raw;
    } authority;
    std::string_view scheme_and_authority;
    std::size_t path_index;
    std::string_view path;
    std::size_t query_index;
    std::string_view query;
    std::size_t fragment_index;
    std::string_view fragment;
    std::string_view raw;
};

std::optional<uri_decomposed> uri_parse(std::string_view uri);

} // namespace ddwaf
